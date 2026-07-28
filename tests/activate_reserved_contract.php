<?php
	require_once __DIR__."/../etc/activate_reserved.php";

	function expect($condition, $message) {
		if (!$condition) {
			fwrite(STDERR, "FAIL: ".$message.PHP_EOL);
			exit(1);
		}
	}

	$now = 1785211200;
	$valid = normalizeActivateReservedRequest([
		"zone" => "ade97a05d3854ea2b37871a7431f7be2",
		"expiration" => strtotime("+9 years", $now),
		"idempotency_key" => "headlessdomains:first-party:claim-123:v1"
	], 42, $now);
	expect($valid["valid"] === true, "valid request should pass");
	expect(strlen($valid["request_hash"]) === 64, "request digest should be SHA-256");
	expect(
		$valid["receipt_action"] === "activateReserved:".hash("sha256", $valid["idempotency_key"]),
		"receipt action should bind the idempotency key"
	);
	expect(
		strlen("ar:".substr(hash("sha256", $valid["idempotency_key"]), 0, 61)) <= 64,
		"advisory lock name should fit MySQL's limit"
	);

	$replay = normalizeActivateReservedRequest([
		"zone" => "ade97a05d3854ea2b37871a7431f7be2",
		"expiration" => strtotime("+9 years", $now),
		"idempotency_key" => "headlessdomains:first-party:claim-123:v1"
	], 42, $now);
	expect($valid["request_hash"] === $replay["request_hash"], "exact replay should be stable");

	$conflict = normalizeActivateReservedRequest([
		"zone" => "ade97a05d3854ea2b37871a7431f7be2",
		"expiration" => strtotime("+8 years", $now),
		"idempotency_key" => "headlessdomains:first-party:claim-123:v1"
	], 42, $now);
	expect($valid["request_hash"] !== $conflict["request_hash"], "changed request should conflict");

	$tooLong = normalizeActivateReservedRequest([
		"zone" => "ade97a05d3854ea2b37871a7431f7be2",
		"expiration" => strtotime("+11 years", $now),
		"idempotency_key" => "headlessdomains:first-party:claim-123:v1"
	], 42, $now);
	expect($tooLong["valid"] === false, "more than ten years should fail");
	expect(
		in_array("expiration_exceeds_ten_year_horizon", $tooLong["errors"]),
		"ten-year error should be explicit"
	);

	$reserved = [
		"account" => null,
		"registrar" => "SkyInclude"
	];
	$privateParent = [
		"owner" => 42,
		"live" => 0
	];
	expect(
		activateReservedEligibility($reserved, $privateParent, 42) === false,
		"owner reservation under private parent should pass"
	);
	$publicParent = $privateParent;
	$publicParent["live"] = 1;
	expect(
		activateReservedEligibility($reserved, $publicParent, 42) === "parent_tld_must_be_private",
		"public parent should fail"
	);
	expect(
		activateReservedEligibility($reserved, $privateParent, 99) === "parent_tld_not_owned_by_authenticated_user",
		"different owner should fail"
	);
	$customerZone = $reserved;
	$customerZone["account"] = 42;
	expect(
		activateReservedEligibility($customerZone, $privateParent, 42) === "zone_is_not_an_owner_reservation",
		"customer-owned zone should fail"
	);

	$implementation = file_get_contents(__DIR__."/../etc/activate_reserved.php");
	foreach (["registerSLD(", "INSERT INTO `sales`", "INSERT INTO `invoices`", "StripeClient"] as $forbidden) {
		expect(
			strpos($implementation, $forbidden) === false,
			"activation implementation must not invoke ".$forbidden
		);
	}

	echo "activateReserved contract checks passed".PHP_EOL;
?>
