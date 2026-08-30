<input type="checkbox" name="simple_jwt_authentication_settings[enable_cors]" <?php checked($enableCors, true); ?> value="1" <?php echo $isGlobal ? 'disabled' : ''; ?> />
<?php if ($isGlobal) : ?>
	<br /><small><?php esc_html_e('Defined in wp-config.php', 'simple-jwt-authentication'); ?></small>
<?php endif; ?>
