<?php
	include "etc/includes.php";

	$tldInfo = getStakedTLD($tld);

	if ($tldInfo) {
		$tld = $tldInfo["tld"];
	}
	else {
		unset($tld);
	}
?>
<!DOCTYPE html>
<html>
<head>
	<?php
		include "etc/head.php";
	?>
</head>
<body>
	<div id="blackout" class="flex">
		<div class="blackoutTable">
			<div class="blackoutCell">
				<?php
					$popoverDirectory = "content/popovers/";
					$popovers = getFiles($popoverDirectory);

					foreach ($popovers as $popover) {
						include $popoverDirectory.$popover;
					}
				?>
			</div>
		</div>
	</div>
	<div class="header">
		<div class="section left">
			<div class="logo">
				<span><?php echo $siteName; ?></span>
			</div>
		</div>
		<div class="section right">
			<div></div>
			<div class="submit item" data-action="dashboard">Dashboard</div>
		</div>
	</div>
	<div class="main" data-user="<?php echo @$userInfo["uuid"]; ?>" data-page="<?php echo $page; ?>" data-tld="<?php echo @$tld; ?>">
		<div class="body">
			<div class="holder">
				<?php
					include "content/domains.php";
				?>
			</div>
			<div class="footer">&copy; <?php echo date("Y"); ?> Eskimo Software</div>
		</div>
	</div>

</body>
</html>