<h2><?php esc_html_e('Simple JWT Authentication API Tokens', 'simple-jwt-authentication'); ?></h2>
<table class="table widefat striped">
	<thead>
		<tr>
			<th><?php esc_html_e('Token UUID', 'simple-jwt-authentication'); ?></th>
			<th><?php esc_html_e('Expires', 'simple-jwt-authentication'); ?></th>
			<th><?php esc_html_e('Last used', 'simple-jwt-authentication'); ?></th>
			<th><?php esc_html_e('IP', 'simple-jwt-authentication'); ?></th>
			<th><?php esc_html_e('User Agent', 'simple-jwt-authentication'); ?></th>
			<th></th>
		</tr>
	</thead>
	<tbody>
		<?php if (!empty($tokens)) : ?>
			<?php
			$currentUrl = remove_query_arg(['revoked', 'removed', 'jwtupdated'], wp_unslash($_SERVER['REQUEST_URI'] ?? ''));
			$revokeNonce    = wp_create_nonce('jwt_revoke_token');
			$revokeAllNonce = wp_create_nonce('jwt_revoke_all_tokens');
			$removeNonce    = wp_create_nonce('jwt_remove_expired_tokens');
			?>
			<?php foreach ($tokens as $token) : ?>
				<?php
				$revokeUrl = add_query_arg([
					'revoke_token' => rawurlencode($token['uuid']),
					'_wpnonce'     => $revokeNonce,
				], $currentUrl);
				?>
				<tr>
					<td><?php echo esc_html($token['uuid']); ?></td>
					<td><?php echo esc_html(date_i18n('Y-m-d H:i:s', $token['expires'])); ?></td>
					<td><?php echo esc_html(date_i18n('Y-m-d H:i:s', $token['last_used'])); ?></td>
					<td>
						<?php echo esc_html($token['ip']); ?>
						<a href="<?php echo esc_url(sprintf('https://ipinfo.io/%s', $token['ip'])); ?>" target="_blank" rel="noopener" class="button-link" title="<?php esc_attr_e('Look up IP location', 'simple-jwt-authentication'); ?>">
							<?php esc_html_e('Lookup', 'simple-jwt-authentication'); ?>
						</a>
					</td>
					<td><?php echo esc_html($token['ua']); ?></td>
					<td>
						<a href="<?php echo esc_url($revokeUrl); ?>" title="<?php esc_attr_e('Revokes this token from being used any further.', 'simple-jwt-authentication'); ?>" class="button-secondary">
							<?php esc_html_e('Revoke', 'simple-jwt-authentication'); ?>
						</a>
					</td>
				</tr>
			<?php endforeach; ?>
			<tr>
				<td colspan="6" align="right">
					<a href="<?php echo esc_url(add_query_arg(['revoke_all_tokens' => '1', '_wpnonce' => $revokeAllNonce], $currentUrl)); ?>" class="button-secondary" title="<?php esc_attr_e('Doing this will require the user to login again on all devices.', 'simple-jwt-authentication'); ?>">
						<?php esc_html_e('Revoke all tokens', 'simple-jwt-authentication'); ?>
					</a>
					<a href="<?php echo esc_url(add_query_arg(['remove_expired_tokens' => '1', '_wpnonce' => $removeNonce], $currentUrl)); ?>" class="button-secondary" title="<?php esc_attr_e('Doing this will not affect logged in devices for this user.', 'simple-jwt-authentication'); ?>">
						<?php esc_html_e('Remove all expired tokens', 'simple-jwt-authentication'); ?>
					</a>
				</td>
			</tr>
		<?php else : ?>
			<tr>
				<td colspan="6"><?php esc_html_e('No tokens generated.', 'simple-jwt-authentication'); ?></td>
			</tr>
		<?php endif; ?>
	</tbody>
</table>
