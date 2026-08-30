<input type="text" name="simple_jwt_authentication_settings[reset_url_template]" value="<?php echo esc_attr($template); ?>" <?php echo $isGlobal ? 'readonly' : ''; ?> size="50" autocomplete="off" placeholder="myapp://reset-password?key={key}&login={login}" />
<?php if ($isGlobal) : ?>
	<br /><small><?php esc_html_e('Defined in wp-config.php', 'simple-jwt-authentication'); ?></small>
<?php else : ?>
	<br /><small>
		<?php esc_html_e('Optional. Replace the wp-login.php reset link in the email with a custom URL, e.g. a mobile app deep link.', 'simple-jwt-authentication'); ?>
		<br /><?php esc_html_e('Placeholders: {key} = reset key, {login} = username.', 'simple-jwt-authentication'); ?>
	</small>
<?php endif; ?>
