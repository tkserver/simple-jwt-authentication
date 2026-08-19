<input type="text" name="simple_jwt_authentication_settings[secret_key]" value="<?php echo esc_attr($secret_key); ?>" <?php echo $is_global ? 'readonly' : ''; ?> size="50" autocomplete="off" />
<?php if ($is_global) : ?>
	<br /><small><?php esc_html_e('Defined in wp-config.php', 'simple-jwt-authentication'); ?></small>
<?php else : ?>
	<br /><small><?php esc_html_e('Should be a long string of letters, numbers and symbols.', 'simple-jwt-authentication'); ?></small>
<?php endif; ?>
