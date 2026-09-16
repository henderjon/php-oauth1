<?php

namespace BasicLti1;

/**
 * The two protocol-identifying parameters every Basic LTI launch carries, and the one launch-
 * specific parameter the spec requires. Fixed for both LTI 1.0 and LTI 1.1: the launch protocol
 * itself did not change between them - LTI 1.1 only added the Basic Outcomes Service on top,
 * which is out of this package's scope for now.
 */
final class Launch {

	public const MESSAGE_TYPE_PARAM = 'lti_message_type';
	public const MESSAGE_TYPE = 'basic-lti-launch-request';

	public const VERSION_PARAM = 'lti_version';
	public const VERSION = 'LTI-1p0';

	public const RESOURCE_LINK_ID_PARAM = 'resource_link_id';

}
