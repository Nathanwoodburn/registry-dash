<?php
	/**
	 * Validate and normalize the payment-free reserved-domain activation input.
	 *
	 * This helper deliberately has no HTTP or database dependency so its safety
	 * contract can be checked without production credentials.
	 */
	function normalizeActivateReservedRequest($data, $user, $now = null) {
		$now = $now ?: time();
		$zone = trim((string)@$data["zone"]);
		$key = trim((string)@$data["idempotency_key"]);
		$expirationRaw = @$data["expiration"];
		$expiration = filter_var($expirationRaw, FILTER_VALIDATE_INT);
		$errors = [];

		if (!$user) {
			$errors[] = "authentication_required";
		}
		if (!preg_match("/^[a-fA-F0-9]{32,64}$/", $zone)) {
			$errors[] = "invalid_reserved_zone";
		}
		if (
			strlen($key) < 8
			|| strlen($key) > 120
			|| !preg_match("/^[A-Za-z0-9:._-]+$/", $key)
		) {
			$errors[] = "invalid_idempotency_key";
		}
		if ($expiration === false || $expiration <= $now) {
			$errors[] = "expiration_must_be_in_the_future";
		}
		$maximumExpiration = strtotime("+10 years", $now);
		if ($expiration !== false && $expiration > $maximumExpiration) {
			$errors[] = "expiration_exceeds_ten_year_horizon";
		}

		$normalized = [
			"zone" => strtolower($zone),
			"expiration" => $expiration === false ? null : (Int)$expiration,
			"user" => (Int)$user
		];
		$requestHash = hash("sha256", json_encode($normalized, JSON_UNESCAPED_SLASHES));

		return [
			"valid" => count($errors) === 0,
			"errors" => $errors,
			"zone" => $normalized["zone"],
			"expiration" => $normalized["expiration"],
			"user" => $normalized["user"],
			"idempotency_key" => $key,
			"receipt_action" => "activateReserved:".hash("sha256", $key),
			"request_hash" => $requestHash
		];
	}

	function activateReservedEligibility($zone, $staked, $user) {
		if (!$zone) {
			return "reserved_zone_not_found";
		}
		if ($zone["account"] !== null || $zone["registrar"] === null) {
			return "zone_is_not_an_owner_reservation";
		}
		if (!$staked || (Int)$staked["owner"] !== (Int)$user) {
			return "parent_tld_not_owned_by_authenticated_user";
		}
		if ((Int)$staked["live"] !== 0) {
			return "parent_tld_must_be_private";
		}
		return false;
	}

	function activateReservedError($message, $code) {
		return [
			"success" => false,
			"message" => $message,
			"code" => $code
		];
	}

	/**
	 * Activate one existing reservation under the authenticated API account.
	 *
	 * The receipt uses the existing log table. A named MySQL lock serializes a
	 * given idempotency key so exact retries are safe without a schema change.
	 */
	function activateReservedDomain($request, $user) {
		if (!$request["valid"]) {
			return activateReservedError(
				"Invalid reserved-domain activation request.",
				$request["errors"][0]
			);
		}

		if (!@$GLOBALS["remoteSQL"]) {
			initSQL();
		}
		$pdo = $GLOBALS["remoteSQL"];
		// Keep the advisory-lock name within MySQL's 64-character limit.
		$lockName = "ar:".substr(hash("sha256", $request["idempotency_key"]), 0, 61);
		$lockStatement = $pdo->prepare("SELECT GET_LOCK(?, 5) AS `locked`");
		$lockStatement->execute([$lockName]);
		$locked = (Int)@$lockStatement->fetch()["locked"];
		if ($locked !== 1) {
			return activateReservedError(
				"Could not acquire the activation lock.",
				"activation_lock_unavailable"
			);
		}

		try {
			$pdo->beginTransaction();

			$receiptStatement = $pdo->prepare(
				"SELECT `domain`,`reason` FROM `log` WHERE `action` = ? ORDER BY `ai` DESC LIMIT 1 FOR UPDATE"
			);
			$receiptStatement->execute([$request["receipt_action"]]);
			$receipt = $receiptStatement->fetch();

			$zoneStatement = $pdo->prepare(
				"SELECT * FROM `".$GLOBALS["sqlDatabaseDNS"]."`.`domains` WHERE `uuid` = ? FOR UPDATE"
			);
			$zoneStatement->execute([$request["zone"]]);
			$zone = $zoneStatement->fetch();

			if ($receipt) {
				$exactReceipt = (
					$receipt["domain"] === $request["zone"]
					&& hash_equals($receipt["reason"], $request["request_hash"])
				);
				$exactState = (
					$zone
					&& (Int)$zone["account"] === (Int)$user
					&& (Int)$zone["expiration"] === (Int)$request["expiration"]
				);
				$pdo->commit();
				if (!$exactReceipt || !$exactState) {
					return activateReservedError(
						"The idempotency key has already been used for different data or the activated state changed.",
						"idempotency_conflict"
					);
				}
				return [
					"success" => true,
					"data" => [
						"domain" => $zone["name"],
						"zone" => $request["zone"],
						"expiration" => (Int)$request["expiration"],
						"state" => "existing",
						"idempotent" => true,
						"payment_created" => false,
						"sale_created" => false,
						"legacy_dns_imported" => false
					]
				];
			}

			$tld = tldForDomain(@$zone["name"]);
			$stakedStatement = $pdo->prepare(
				"SELECT * FROM `staked` WHERE `tld` = ? FOR UPDATE"
			);
			$stakedStatement->execute([$tld]);
			$staked = $stakedStatement->fetch();
			$eligibilityError = activateReservedEligibility($zone, $staked, $user);
			if ($eligibilityError) {
				$pdo->rollBack();
				return activateReservedError(
					"The reserved domain is not eligible for activation.",
					$eligibilityError
				);
			}

			$updateStatement = $pdo->prepare(
				"UPDATE `".$GLOBALS["sqlDatabaseDNS"]."`.`domains` SET `account` = ?, `expiration` = ?, `renew` = 0 WHERE `uuid` = ? AND `account` IS NULL"
			);
			$updateStatement->execute([
				(Int)$user,
				(Int)$request["expiration"],
				$request["zone"]
			]);
			if ($updateStatement->rowCount() !== 1) {
				$pdo->rollBack();
				return activateReservedError(
					"The reservation changed before it could be activated.",
					"reserved_zone_state_changed"
				);
			}

			$receiptInsert = $pdo->prepare(
				"INSERT INTO `log` (`domain`,`action`,`reason`,`time`) VALUES (?,?,?,?)"
			);
			$receiptInsert->execute([
				$request["zone"],
				$request["receipt_action"],
				$request["request_hash"],
				time()
			]);
			$pdo->commit();

			return [
				"success" => true,
				"data" => [
					"domain" => $zone["name"],
					"zone" => $request["zone"],
					"expiration" => (Int)$request["expiration"],
					"state" => "activated",
					"idempotent" => false,
					"payment_created" => false,
					"sale_created" => false,
					"legacy_dns_imported" => false
				]
			];
		}
		catch (Throwable $error) {
			if ($pdo->inTransaction()) {
				$pdo->rollBack();
			}
			return activateReservedError(
				"Reserved-domain activation failed.",
				"activation_failed"
			);
		}
		finally {
			$releaseStatement = $pdo->prepare("SELECT RELEASE_LOCK(?)");
			$releaseStatement->execute([$lockName]);
		}
	}
?>
