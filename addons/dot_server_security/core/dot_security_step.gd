@tool
class_name GSSecurityStep
extends Resource

## One rung of a rule's escalation ladder: warn, then gag briefly, then gag properly, then remove.
## A flat rule has one answer for a first offence and a fiftieth. Offences past the last step repeat it, since a ladder that fell back to nothing would reward persistence.

@export var action: GSSecurityAction.Kind = GSSecurityAction.Kind.WARN

## Seconds the action lasts. 0 is permanent for a ban and meaningless for a kick.
@export var duration_sec: int = 0

## Told to the player when this step is applied. Empty uses the rule's reason.
@export var message: String = ""


static func of(
	p_action: GSSecurityAction.Kind,
	p_duration_sec: int = 0,
	p_message: String = ""
) -> GSSecurityStep:
	var step := GSSecurityStep.new()
	step.action = p_action
	step.duration_sec = p_duration_sec
	step.message = p_message
	return step


static func from_dictionary(raw: Dictionary) -> GSResult:
	var step := GSSecurityStep.new()

	var action_name := str(raw.get("action", "warn"))
	var parsed := GSSecurityAction.parse_kind(action_name)

	if parsed < 0:
		return GSResult.fail(
			GSError.CODE_INVALID,
			"'%s' is not an action." % action_name,
			"try none, warn, gag, voice_mute, silence, kick or ban"
		)

	step.action = parsed as GSSecurityAction.Kind
	step.duration_sec = int(raw.get("duration_sec", raw.get("duration", 0)))
	step.message = str(raw.get("message", ""))

	if step.duration_sec < 0:
		return GSResult.fail(
			GSError.CODE_INVALID, "A duration cannot be negative."
		)

	return GSResult.success(step)


func to_dictionary() -> Dictionary:
	var out := {"action": GSSecurityAction.kind_name(action)}
	if duration_sec > 0:
		out["duration_sec"] = duration_sec
	if message != "":
		out["message"] = message
	return out


func describe() -> String:
	var name := GSSecurityAction.kind_name(action)
	if GSSecurityAction.takes_duration(action) and duration_sec > 0:
		return "%s %s" % [name, GSSecurityAction.format_duration(duration_sec)]
	return name
