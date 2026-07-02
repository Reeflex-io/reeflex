<?php
/**
 * Plugin Name:  Reeflex Test Abilities
 * Description:  Registers harmless test abilities (read + delete on a private
 *               "reeflex_test" post type) so you can exercise the Reeflex gate
 *               end-to-end on a live WordPress install. SAFE: it only ever
 *               touches its own reeflex_test posts, never your real content.
 *               Remove this plugin after testing.
 * Version:      0.1.0
 * Requires PHP: 7.4
 * Author:       Reeflex
 * License:      Apache-2.0
 *
 * WHY THIS EXISTS
 * ---------------
 * Reeflex guards the Abilities API seam. But a fresh WordPress has no
 * write-abilities registered, so there is nothing to test the gate against.
 * This plugin registers a few deliberately-shaped abilities whose names and
 * inputs trigger the Reeflex normalizer's rules (delete verb, bulk >= 20,
 * force_delete -> irreversible, site-wide -> systemic), so you can watch
 * Reeflex return allow / hold / deny on real HTTP calls.
 *
 * It creates and deletes ONLY posts of type `reeflex_test`. It cannot touch
 * your real posts, pages, products, or users.
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

/**
 * Register a private post type to act as the safe blast area for tests.
 * Not public, not in REST on its own — the abilities are the only way in.
 */
add_action(
	'init',
	static function (): void {
		register_post_type(
			'reeflex_test',
			array(
				'label'        => 'Reeflex Test Items',
				'public'       => false,
				'show_ui'      => true,
				'show_in_menu' => true,
				'supports'     => array( 'title' ),
			)
		);
	}
);

/**
 * Step 1 — register the ability category (must exist before the abilities).
 */
add_action(
	'wp_abilities_api_categories_init',
	static function (): void {
		if ( ! function_exists( 'wp_register_ability_category' ) ) {
			return;
		}
		wp_register_ability_category(
			'reeflex-test',
			array(
				'label'       => __( 'Reeflex Test', 'reeflex-test' ),
				'description' => __( 'Safe abilities for exercising the Reeflex gate.', 'reeflex-test' ),
			)
		);
	}
);

/**
 * Step 2 — register the test abilities.
 *
 * All destructive abilities require the `delete_posts` capability, so an
 * unauthenticated caller is stopped by WordPress before Reeflex is even
 * consulted. With a valid Application Password, the call reaches the gate.
 */
add_action(
	'wp_abilities_api_init',
	static function (): void {
		if ( ! function_exists( 'wp_register_ability' ) ) {
			return;
		}

		// --- READ: expected Reeflex verdict = allow ------------------------
		wp_register_ability(
			'reeflex-test/get-item',
			array(
				'label'               => __( 'Get a test item', 'reeflex-test' ),
				'description'         => __( 'Reads a single reeflex_test post. Read-only.', 'reeflex-test' ),
				'category'            => 'reeflex-test',
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'id' => array( 'type' => 'integer' ),
					),
				),
				'output_schema'       => array( 'type' => 'object' ),
				'execute_callback'    => 'reeflex_test_get_item',
				'permission_callback' => static function () {
					return current_user_can( 'read' );
				},
				// NOTE: no readonly/destructive annotation on purpose. Without them
				// the /run endpoint accepts POST (input in the JSON body), so the
				// test script can use one uniform call shape for every scenario.
				// Reeflex decides on the ability NAME + INPUT, never on the HTTP
				// verb, so this simplification does not change any verdict.
				'meta'                => array(
					'show_in_rest' => true,
				),
			)
		);

		// --- DELETE (soft, single): expected verdict = allow ---------------
		wp_register_ability(
			'reeflex-test/delete-item',
			array(
				'label'               => __( 'Delete test items', 'reeflex-test' ),
				'description'         => __( 'Deletes one or more reeflex_test posts. Pass ids[] and optional force_delete.', 'reeflex-test' ),
				'category'            => 'reeflex-test',
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'ids'          => array(
							'type'  => 'array',
							'items' => array( 'type' => 'integer' ),
						),
						'force_delete' => array( 'type' => 'boolean' ),
					),
					'required'   => array( 'ids' ),
				),
				'output_schema'       => array( 'type' => 'object' ),
				'execute_callback'    => 'reeflex_test_delete_items',
				'permission_callback' => static function () {
					return current_user_can( 'delete_posts' );
				},
				// POST endpoint (no destructive annotation) — see note above.
				'meta'                => array(
					'show_in_rest' => true,
				),
			)
		);

		// --- DELETE site-wide: expected verdict = deny (systemic) ----------
		wp_register_ability(
			'reeflex-test/delete-site-wide-data',
			array(
				'label'               => __( 'Delete ALL test items (systemic)', 'reeflex-test' ),
				'description'         => __( 'Deletes every reeflex_test post. Shaped to trigger the systemic/deny rule.', 'reeflex-test' ),
				'category'            => 'reeflex-test',
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'force_delete' => array( 'type' => 'boolean' ),
					),
				),
				'output_schema'       => array( 'type' => 'object' ),
				'execute_callback'    => 'reeflex_test_delete_all',
				'permission_callback' => static function () {
					return current_user_can( 'delete_others_posts' );
				},
				// POST endpoint (no destructive annotation) — see note above.
				'meta'                => array(
					'show_in_rest' => true,
				),
			)
		);
	}
);

/**
 * Execute callback — read one item.
 *
 * @param array $input Ability input.
 * @return array
 */
function reeflex_test_get_item( $input ) {
	$id = isset( $input['id'] ) ? (int) $input['id'] : 0;
	$post = $id ? get_post( $id ) : null;
	return array(
		'found' => ( $post && 'reeflex_test' === $post->post_type ),
		'id'    => $id,
	);
}

/**
 * Execute callback — delete the given reeflex_test items.
 *
 * Guard rails: only ever deletes posts of type reeflex_test. Any id that is
 * not a reeflex_test post is skipped. This runs ONLY if Reeflex allowed the
 * action (otherwise the gate returned WP_Error before reaching here).
 *
 * @param array $input Ability input: ids[] and optional force_delete.
 * @return array
 */
function reeflex_test_delete_items( $input ) {
	$ids   = isset( $input['ids'] ) && is_array( $input['ids'] ) ? array_map( 'intval', $input['ids'] ) : array();
	$force = ! empty( $input['force_delete'] );
	$deleted = array();

	foreach ( $ids as $id ) {
		$post = get_post( $id );
		if ( $post && 'reeflex_test' === $post->post_type ) {
			wp_delete_post( $id, $force );
			$deleted[] = $id;
		}
	}

	return array(
		'deleted' => $deleted,
		'count'   => count( $deleted ),
		'forced'  => $force,
	);
}

/**
 * Execute callback — delete ALL reeflex_test items.
 *
 * @param array $input Ability input.
 * @return array
 */
function reeflex_test_delete_all( $input ) {
	$force = ! empty( $input['force_delete'] );
	$posts = get_posts(
		array(
			'post_type'   => 'reeflex_test',
			'numberposts' => -1,
			'post_status' => 'any',
			'fields'      => 'ids',
		)
	);

	foreach ( $posts as $id ) {
		wp_delete_post( (int) $id, $force );
	}

	return array(
		'deleted' => count( $posts ),
		'forced'  => $force,
	);
}
