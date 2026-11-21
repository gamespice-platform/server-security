@tool
class_name GSSecurityWatch
extends Node

## Wires the guard to everything on the server worth watching: one node rather than five, every source an optional toggle.
## Nothing here names GameSpice Chat or GameSpice Auth (optional; a missing class_name fails to parse and the guard would stop existing); they are reached through [GSRegistry] and their signals connected by name.
## Sources and the events they give: chat (chat.*), connections (connect.*), RCON (rcon.*), the console (command.denied), GameSpice Auth (auth.*).

const CHANNEL := "security"

@export_group("Wiring")

## The guard to report to. Defaults to whichever one is in [GSRegistry].
@export var guard_ref: GSNodeRef = null

@export_group("Sources")

## Watch text chat: the server's own path and GameSpice Chat's router if present.
@export var watch_chat: bool = true

## Watch connections, rejections and reconnect churn.
@export var watch_connections: bool = true

## Watch RCON authentication failures. [b]Leave this on.[/b]
@export var watch_rcon: bool = true

## Watch commands refused for want of permission.
@export var watch_commands: bool = true

## Watch GameSpice Auth, when it is installed.
@export var watch_auth: bool = true

var guard: GSSecurityManager = null
var server: GSServer = null

## subject -> Array of [text, unix_time], for the duplicate check.
var _recent_text: Dictionary = {}

## address -> unix time of last connect, for the churn check.
var _connected_at: Dictionary = {}

var _wired: PackedStringArray = PackedStringArray()


func _ready() -> void:
	if Engine.is_editor_hint():
		return

	if guard_ref == null:
		guard_ref = GSNodeRef.of_service(GSSecurityManager.SERVICE)

	if guard_ref.mode == GSNodeRef.Mode.REGISTRY \
			and GSRegistry.get_service(guard_ref.service) == null:
		var waited := await GSRegistry.await_service(guard_ref.service, 10.0)
		if not waited.ok:
			GSLog.warn(CHANNEL, "no security manager to report to")
			return

	guard = guard_ref.resolve_or_null(self, CHANNEL) as GSSecurityManager
	if guard == null:
		GSLog.warn(CHANNEL, "guard_ref did not resolve to a GSSecurityManager")
		return

	server = guard.server
	if server == null:
		GSLog.warn(CHANNEL, "the guard is not attached to a server yet")
		return

	_wire()

	GSLog.info(
		CHANNEL, "watching", {"sources": ", ".join(Array(_wired))}
	)


func _wire() -> void:
	if watch_chat:
		_wire_server_chat()
		_wire_chat_router()
	if watch_connections:
		_wire_connections()
	if watch_rcon:
		_wire_rcon()
	if watch_commands:
		_wire_commands()
	if watch_auth:
		_wire_auth()



func _wire_server_chat() -> void:
	if server.chat == null:
		return

	server.chat.message_sent.connect(_on_server_message)
	server.chat.message_blocked.connect(_on_server_message_blocked)
	_wired.append("server chat")


func _on_server_message(
	session: GSClientSession, text: String, _team_only: bool
) -> void:
	_examine_message(session, text)


func _on_server_message_blocked(session: GSClientSession, reason: String) -> void:
	guard.report_session(
		GSSecurityEvent.CHAT_REFUSED, session, 1.0, {"reason": reason}
	)


## GameSpice Chat's router, reached by registry name and connected by signal name.
func _wire_chat_router() -> void:
	var router := GSRegistry.get_service(&"gs_chat_router")
	if router == null or not is_instance_valid(router):
		return

	if router.has_signal("message_accepted"):
		router.connect("message_accepted", _on_router_message)
	if router.has_signal("message_refused"):
		router.connect("message_refused", _on_router_refused)
	if router.has_signal("command_entered"):
		router.connect("command_entered", _on_router_command)

	_wired.append("chat router")


func _on_router_message(message: Object, _recipients: PackedInt32Array) -> void:
	if message == null:
		return

	var peer := int(message.get("peer"))
	var text := str(message.get("text"))
	_examine_message(_session_for(peer), text)


func _on_router_refused(peer: int, code: String, _reason: String) -> void:
	guard.report_session(
		GSSecurityEvent.CHAT_REFUSED, _session_for(peer), 1.0, {"code": code}
	)


func _on_router_command(
	peer: int, command: String, _args: PackedStringArray, _raw: String
) -> void:
	guard.report_session(
		GSSecurityEvent.CHAT_COMMAND, _session_for(peer), 1.0,
		{"command": command}
	)


## Turns one message into every chat event it is an instance of.
## A shouted, repeated link is three events, counted separately because an operator may care about one; reporting only the worst would stop the other rules firing.
func _examine_message(session: GSClientSession, text: String) -> void:
	if session == null:
		return

	guard.report_session(GSSecurityEvent.CHAT_MESSAGE, session, 1.0)

	var config := guard.config
	var subject := GSSecuritySubject.of_session(
		session, GSSecuritySubject.Scope.UID
	)

	if _is_duplicate(subject, text, config):
		guard.report_session(GSSecurityEvent.CHAT_DUPLICATE, session)

	if _is_shouting(text, config):
		guard.report_session(GSSecurityEvent.CHAT_CAPS, session)

	if _has_link(text, config):
		guard.report_session(GSSecurityEvent.CHAT_LINK, session)


func _is_duplicate(
	subject: String, text: String, config: GSSecurityConfig
) -> bool:
	var now := int(Time.get_unix_time_from_system())
	var needle := _normalise(text, config)

	var history: Array = _recent_text.get(subject, [])
	var live: Array = []
	var found := false

	for entry in history:
		var pair: Array = entry
		if now - int(pair[1]) > int(config.duplicate_memory_sec):
			continue
		live.append(pair)
		if str(pair[0]) == needle:
			found = true

	live.append([needle, now])

	if live.size() > config.duplicate_depth:
		live = live.slice(live.size() - config.duplicate_depth)

	_recent_text[subject] = live
	return found


func _normalise(text: String, config: GSSecurityConfig) -> String:
	if not config.duplicate_normalises:
		return text

	# Case, whitespace and punctuation removed. The spammer who adds a full stop
	# each time is the whole reason this is not an exact comparison.
	var out := ""
	for i in range(text.length()):
		var c := text[i]
		if c.is_valid_identifier() or (c >= "0" and c <= "9") \
				or (c >= "a" and c <= "z") or (c >= "A" and c <= "Z"):
			out += c.to_lower()
	return out


static func _is_shouting(text: String, config: GSSecurityConfig) -> bool:
	if text.length() < config.caps_min_length:
		return false

	var letters := 0
	var upper := 0

	for i in range(text.length()):
		var c := text[i]
		var lower := c.to_lower()
		var upper_c := c.to_upper()
		if lower == upper_c:
			# Not a cased character: a digit, a space, punctuation, or a script
			# with no case at all. Counting those would make every message in a
			# language without capitals count as shouting.
			continue
		letters += 1
		if c == upper_c:
			upper += 1

	if letters < config.caps_min_length:
		return false

	return float(upper) / float(letters) >= config.caps_ratio


static func _has_link(text: String, config: GSSecurityConfig) -> bool:
	var lowered := text.to_lower()

	for allowed in config.link_allow:
		if lowered.contains(String(allowed).to_lower()):
			return false

	for marker in config.link_markers:
		if lowered.contains(String(marker).to_lower()):
			return true

	return false



func _wire_connections() -> void:
	server.client_state_changed.connect(_on_client_state)
	server.client_disconnected.connect(_on_client_disconnected)
	_wired.append("connections")


func _on_client_state(session: GSClientSession) -> void:
	if session == null:
		return

	# CONNECTING is the only state every arrival passes through exactly once,
	# which is what makes it the attempt. Counting SPAWNED instead would miss
	# precisely the connections that never finish — the ones a flood is made of.
	if session.state == GSClientSession.State.CONNECTING:
		_connected_at[GSSecuritySubject.normalise_address(session.address)] = \
			int(Time.get_unix_time_from_system())
		guard.report_address(
			GSSecurityEvent.CONNECT_ATTEMPT, session.address, 1.0,
			{"uid": session.uid()}
		)
	elif session.state == GSClientSession.State.REJECTED:
		guard.report_address(
			GSSecurityEvent.CONNECT_REJECTED, session.address, 1.0,
			{"reason": session.reject_reason}
		)


func _on_client_disconnected(session: GSClientSession, _reason: String) -> void:
	if session == null:
		return

	var address := GSSecuritySubject.normalise_address(session.address)
	var began := int(_connected_at.get(address, 0))
	_connected_at.erase(address)

	if began <= 0:
		return

	var lasted := int(Time.get_unix_time_from_system()) - began

	# Churn is the pattern no single connection looks wrong in: every one is
	# legitimate, and the server is still being hammered. A session that reached
	# SPAWNED and played is not churn however short it was.
	if float(lasted) <= guard.config.churn_window_sec \
			and session.spawned_at <= 0:
		guard.report_address(
			GSSecurityEvent.CONNECT_CHURN, session.address, 1.0,
			{"lasted_sec": lasted}
		)



func _wire_rcon() -> void:
	if server.rcon == null:
		return

	server.rcon.auth_failed.connect(_on_rcon_auth_failed)
	server.rcon.command_received.connect(_on_rcon_command)
	_wired.append("rcon")


func _on_rcon_auth_failed(address: String, attempts: int) -> void:
	guard.report_address(
		GSSecurityEvent.RCON_AUTH_FAILED, address, 1.0, {"attempts": attempts}
	)


func _on_rcon_command(address: String, command: String) -> void:
	guard.report_address(
		GSSecurityEvent.RCON_COMMAND, address, 1.0, {"command": command}
	)



## Text GameSpice Server uses for a refusal that was about permission.
## A string coupling, the only one available: `command_executed` fires after the permission check, so only `command_refused` sees a denial, told apart by this prefix. It tells probing from mistyping.
## The self-test asserts the prefix against the real GameSpice Server, since a comment does not fail when the wording changes.
const REFUSAL_PERMISSION := "missing permission"


func _wire_commands() -> void:
	if server.console == null:
		return
	if not server.console.has_signal("command_refused"):
		return

	server.console.command_refused.connect(_on_command_refused)
	_wired.append("commands")


func _on_command_refused(ctx: GSCmdContext, reason: String) -> void:
	# Only a refusal about permission. An unknown command is somebody mistyping,
	# and counting it would fire the rule on ordinary use.
	if not reason.begins_with(REFUSAL_PERMISSION):
		return

	if ctx == null:
		return

	if ctx.session != null:
		guard.report_session(
			GSSecurityEvent.COMMAND_DENIED, ctx.session, 1.0,
			{"command": ctx.command}
		)
	elif ctx.address != "":
		guard.report_address(
			GSSecurityEvent.COMMAND_DENIED, ctx.address, 1.0,
			{"command": ctx.command}
		)


## The session behind a peer id, or null.
func _session_for(peer: int) -> GSClientSession:
	if server == null:
		return null
	return server.session_of(peer)



func _wire_auth() -> void:
	var auth := GSRegistry.get_service(&"gs_auth_server")
	if auth == null or not is_instance_valid(auth):
		return

	if auth.has_signal("rejected"):
		auth.connect("rejected", _on_auth_rejected)

	_wired.append("auth")


func _on_auth_rejected(reason: String, detail: String) -> void:
	# GameSpice Auth reports why, not who. The address is taken from a session still mid-handshake; when none is, the event is dropped,
	# since one attributed to nobody ("somebody, somewhere failed") would ban the next person to connect.
	for session in server.sessions():
		if session.state == GSClientSession.State.AUTHENTICATING:
			guard.report_address(
				GSSecurityEvent.AUTH_FAILED, session.address, 1.0,
				{"reason": reason, "detail": detail}
			)
			return


func describe_lines() -> PackedStringArray:
	var out := PackedStringArray()
	out.append("wired       %s" % (
		", ".join(Array(_wired)) if not _wired.is_empty() else "nothing"
	))
	out.append("tracking    %d chat histories, %d connections" % [
		_recent_text.size(), _connected_at.size()
	])
	return out
