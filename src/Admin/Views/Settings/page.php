<form action="options.php" method="post">
	<h1><?php esc_html_e('Simple JWT Authentication', 'simple-jwt-authentication'); ?></h1>
	<?php
	settings_fields('simple_jwt_authentication');
	do_settings_sections('simple_jwt_authentication');
	submit_button();
	?>
	<h2><?php esc_html_e('Getting started', 'simple-jwt-authentication'); ?></h2>
	<p>
		<?php echo wp_kses_post(sprintf(
			/* translators: %s: documentation URL */
			__('To get started check out the <a href="%s" target="_blank" rel="noopener">documentation</a>', 'simple-jwt-authentication'),
			'https://github.com/jonathan-dejong/simple-jwt-authentication/wiki/Documentation'
		)); ?>
	</p>
</form>
