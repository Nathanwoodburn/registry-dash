<?php
	include "../etc/includes.php";
?>
<div class="section" data-section="settings">
	<div class="title">Settings</div>
	<div class="box">
		<form>
			<table id="settings">
				<tr>
					<td>Support Token</td>
					<td>
						<input type="text" name="token" value="<?php echo $userInfo["token"]; ?>" readonly />
					</td>
				</tr>
				<tr>
					<td>Email</td>
					<td>
						<input type="text" name="email" value="<?php echo $userInfo["email"]; ?>" autocomplete="email" />
					</td>
				</tr>
				<tr>
					<td>Current Password</td>
					<td>
						<input type="password" name="password" autocomplete="current-password" />
					</td>
				</tr>
				<tr>
					<td>New Password</td>
					<td>
						<input type="password" name="new-password" autocomplete="new-password" />
					</td>
				</tr>
			</table>
			<input type="hidden" name="action" value="settings">
			<div class="flex right">
				<div class="submit" data-action="settings">Save</div>
			</div>
		</form>
	</div>
</div>
<div class="section" data-section="billing">
	<div class="title">Billing</div>
	<div class="box">
		<div id="paymentMethods">
			<div id="paymentMethodsTable" class="table"></div>
			<div class="separator"></div>
		</div>
		<form id="addPaymentMethod">
			<table id="billing">
				<tbody>
					<tr>
						<td>Card Number</td>
						<td>
							<input type="text" data-stripe="number" placeholder="1234 1234 1234 1234" autocomplete="cc-number" />
						</td>
					</tr>
					<tr>
						<td>Expiration</td>
						<td>
							<input type="text" data-stripe="exp" placeholder="<?php echo date("m")."/".(date("y") + 3); ?>" autocomplete="cc-exp" />
						</td>
					</tr>
					<tr>
						<td>CVC</td>
						<td>
							<input type="text" data-stripe="cvc" placeholder="123" autocomplete="cc-csc" />
						</td>
					</tr>
				</tbody>
			</table>
			<input type="hidden" name="action" value="addPaymentMethod">
			<div class="flex right">
				<div class="submit" data-action="addPaymentMethod">Add Card</div>
			</div>
		</form>
	</div>
</div>