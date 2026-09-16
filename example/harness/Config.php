<?php

namespace Harness;

/**
 * The shared setup a real Tool Consumer and Tool Provider agree on out of band (a registration
 * form, an admin screen) before any launch happens - hardcoded here since this is a local demo
 * harness, not a real integration.
 */
final class Config {

	public const TOOL_CONSUMER_URL = 'http://127.0.0.1:8091/';
	public const TOOL_PROVIDER_URL = 'http://127.0.0.1:8092/';

	public const CONSUMER_KEY = 'harness-consumer-key';
	public const CONSUMER_SECRET = 'harness-shared-secret';

	public const NONCE_CACHE_FILE = __DIR__ . '/var/nonce-cache.json';

}
