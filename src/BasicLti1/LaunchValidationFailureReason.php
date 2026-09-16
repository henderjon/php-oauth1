<?php

namespace BasicLti1;

/**
 * Why a launch was rejected as invalid Basic LTI, independent of whether it was signed
 * correctly - attached to Exceptions\InvalidLaunchException so a caller can log or respond
 * differently without parsing the exception message.
 */
enum LaunchValidationFailureReason {

	case MissingOrInvalidMessageType;
	case MissingOrInvalidVersion;
	case MissingResourceLinkId;

}
