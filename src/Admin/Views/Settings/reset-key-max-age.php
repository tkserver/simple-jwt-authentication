<input type="number" name="simple_jwt_authentication_settings[reset_key_max_age_hours]" value="<?php echo esc_attr($maxAge); ?>" min="0" step="1" size="5" <?php echo $isGlobal ? 'readonly' : ''; ?> />
<?php if ($isGlobal) : ?>
	<br /><small><?php esc_html_e('Defined in wp-config.php', 'simple-jwt-authentication'); ?></small>
<?php else : ?>
	<br /><small>
		<?php esc_html_e('Optional. Reset keys are invalidated (and rotated on re-request) after this many hours. 0 = use WordPress core\'s default expiry (24 hours).', 'simple-jwt-authentication'); ?>
	</small>
<?php endif; ?>
