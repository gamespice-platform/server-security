extends "res://examples/security_selftest_mid.gd"

## Ban feed, anti-cheat and console sections, and the run order of the whole suite.



func _run_selftest() -> void:
	print("=== self-test ===")
	print("")

	_test_attach()
	_test_windows()
	_test_subjects()
	_test_rules()
	_test_escalation()
	_test_exemptions()
	_test_dry_run()
	_test_policy_json()
	_test_chat_detection()
	_test_couplings()
	_test_ban_index()
	_test_ban_feed_parsing()
	_test_ban_feed_auth()
	await _test_ban_feed_admission()
	_test_anticheat()
	_test_without_moderation()
	_test_console()

	print("")
	# The two guards, as the last two checks. See docs/testing.md.
	_check(
		"every section ran to its last line (%d of %d)" % [_completed, SECTIONS],
		_completed == _entered and _entered == SECTIONS
	)
	_check(
		"every check ran (%d of %d)" % [_passed + _failed + 1, CHECKS],
		_passed + _failed + 1 == CHECKS
	)
	print("%d passed, %d failed" % [_passed, _failed])

	server.shutdown("self-test complete")
	get_tree().quit(1 if _failed > 0 else 0)




func _test_ban_index() -> void:
	print("")
	_section("[ban index]")

	var index := GSBanIndex.new()
	index.add_uid("banned-account", "listed")
	index.add_address("203.0.113.7", "listed")
	index.add_address("198.51.100.0/24", "a whole range")

	_check("a listed account is found",
		index.reason_for_uid("banned-account") != "")
	_check("an unlisted account is not",
		index.reason_for_uid("someone-else") == "")
	_check("a listed address is found",
		index.reason_for_address("203.0.113.7") != "")

	# A /24 is 256 addresses and must not be expanded into 256 entries; a /16
	# would be sixty-five thousand for one line of somebody's blocklist.
	_check("an address inside a range is found",
		index.reason_for_address("198.51.100.42") != "")
	_check("an address outside it is not",
		index.reason_for_address("198.51.101.42") == "")
	_check("the range was not expanded", index.addresses.size() == 1)

	_check("a mapped address matches its plain form",
		index.reason_for_address("::ffff:203.0.113.7") != "")

	_check("an address is recognised as one",
		GSBanIndex.looks_like_address("10.0.0.1"))
	_check("a range is recognised as one",
		GSBanIndex.looks_like_address("10.0.0.0/8"))
	_check("an account id is not",
		not GSBanIndex.looks_like_address("player-12345"))
	_check("nor is nonsense that looks numeric",
		not GSBanIndex.looks_like_address("999.999.999.999"))
	_done()


func _test_ban_feed_parsing() -> void:
	print("")
	_section("[ban feed parsing]")

	var feed := GSBanFeed.of(&"t", "https://example.org/list")

	# A bare array of strings: the commonest shape there is, and it says
	# nothing about what its entries are.
	var bare := GSBanFeeds.parse_payload(feed, ["1.2.3.4", "player-99"])
	_check("a bare list parses", bare.ok)
	_check("an address entry is guessed",
		bare.ok and (bare.value as Array)[0].has("address"))
	_check("an account entry is guessed",
		bare.ok and (bare.value as Array)[1].has("uid"))

	# An array of objects with differently-named fields.
	var objects := GSBanFeeds.parse_payload(feed, [
		{"user_id": "abc", "reason": "cheating"},
		{"ip_address": "5.6.7.8"},
	])
	_check("objects parse", objects.ok)
	_check("an aliased id field is found",
		objects.ok and str((objects.value as Array)[0]["uid"]) == "abc")
	_check("the reason comes across",
		objects.ok and str((objects.value as Array)[0]["reason"]) == "cheating")
	_check("an aliased address field is found",
		objects.ok and (objects.value as Array)[1].has("address"))

	# A wrapper object, with and without a configured path.
	var wrapped := GSBanFeeds.parse_payload(feed, {"data": ["9.9.9.9"]})
	_check("a conventional wrapper is unwrapped",
		wrapped.ok and (wrapped.value as Array).size() == 1)

	feed.list_path = "result.bans"
	var pathed := GSBanFeeds.parse_payload(
		feed, {"result": {"bans": ["8.8.8.8"]}}
	)
	_check("an explicit path is followed",
		pathed.ok and (pathed.value as Array).size() == 1)
	_check("a wrong path is refused",
		not GSBanFeeds.parse_payload(feed, {"nothing": []}).ok)
	feed.list_path = ""

	# The split-object shape.
	var split := GSBanFeeds.parse_payload(
		feed, {"uids": ["a", "b"], "ips": ["1.1.1.1"]}
	)
	_check("a split object parses",
		split.ok and (split.value as Array).size() == 3)

	# An expired entry enforced until the next fetch is how somebody stays
	# banned for a week after their day was up.
	var expired := GSBanFeeds.parse_payload(feed, [
		{"uid": "gone", "expires": 1},
		{"uid": "current", "expires": 99999999999},
	])
	_check("an expired entry is dropped",
		expired.ok and (expired.value as Array).size() == 1)
	_check("and a live one is kept",
		expired.ok and str((expired.value as Array)[0]["uid"]) == "current")

	_check("something that is not a list is refused",
		not GSBanFeeds.parse_payload(feed, 42).ok)
	_done()


func _test_ban_feed_auth() -> void:
	print("")
	_section("[ban feed authentication]")

	var feed := GSBanFeed.of(&"auth", "https://example.org/list")

	feed.auth = GSBanFeed.Auth.NONE
	_check("a public feed sends no credential",
		not feed.headers().has("Authorization"))

	feed.auth = GSBanFeed.Auth.BEARER
	feed.token = "a-jwt-or-an-api-key"
	_check("a bearer token is a bearer header",
		str(feed.headers()["Authorization"]) == "Bearer a-jwt-or-an-api-key")

	feed.auth = GSBanFeed.Auth.BASIC
	feed.username = "user"
	feed.token = "pass"
	_check("basic auth is base64 of user:pass",
		str(feed.headers()["Authorization"])
			== "Basic " + Marshalls.utf8_to_base64("user:pass"))

	feed.auth = GSBanFeed.Auth.HEADER
	feed.header_name = "X-Api-Key"
	feed.token = "k"
	_check("a custom header carries the key",
		str(feed.headers()["X-Api-Key"]) == "k")

	feed.auth = GSBanFeed.Auth.QUERY
	feed.query_name = "key"
	feed.token = "q"
	_check("a query credential reaches the url",
		feed.effective_url().contains("key=q"))
	_check("and is appended correctly to a url with a query",
		GSBanFeed.parse_auth("query") == GSBanFeed.Auth.QUERY)

	feed.auth = GSBanFeed.Auth.HMAC
	feed.token = "secret"
	var signed := feed.headers()
	_check("hmac sends a timestamp", signed.has("X-GS-Timestamp"))
	_check("hmac sends a nonce", signed.has("X-GS-Nonce"))
	_check("hmac sends a signature", signed.has("X-GS-Signature"))
	_check("nothing replayable is sent",
		not str(signed.get("X-GS-Signature", "")).contains("secret"))

	# The token is a secret and must not be reachable from the environment or
	# argv, both of which are readable by other processes and end up in `ps`.
	_check("the token is marked sensitive",
		GSBanFeed.sensitive_keys().has("token"))

	var insecure := GSBanFeed.of(&"i", "http://example.org/list")
	_check("plain http is refused", not insecure.validate().ok)
	insecure.allow_insecure = true
	_check("...unless explicitly allowed", insecure.validate().ok)

	var no_token := GSBanFeed.of(&"n", "https://example.org/list")
	no_token.auth = GSBanFeed.Auth.BEARER
	_check("a feed needing a credential and having none is refused at boot",
		not no_token.validate().ok)

	_check("jwt is accepted as a spelling of bearer",
		GSBanFeed.parse_auth("jwt") == GSBanFeed.Auth.BEARER)
	_check("fail_closed is accepted as a spelling of refuse_all",
		GSBanFeed.parse_failure("fail_closed")
			== GSBanFeed.OnFailure.REFUSE_ALL)
	_done()


func _test_ban_feed_admission() -> void:
	print("")
	_section("[ban feed admission]")

	# Registered before the feeds node, so the chaining path has something to
	# find. Two ban sources with neither knowing about the other is a
	# deployment enforcing exactly one of them.
	var upstream := StubBanSource.new()
	GSRegistry.register(GSBanFeeds.BAN_SOURCE, upstream)

	feeds = GSBanFeeds.new()
	feeds.name = "BanFeeds"
	feeds.feeds_file = ""
	feeds.fetch_on_ready = false
	add_child(feeds)
	await get_tree().process_frame

	_check("it registered as the ban source",
		GSRegistry.get_service(GSBanFeeds.BAN_SOURCE) == feeds)
	_check("and chained to what was there before",
		feeds.previous_source == upstream)

	feeds.index.add_uid("listed-account", "network: cheating")
	feeds.index.add_address("203.0.113.99", "network: proxy")

	_check("an unlisted player is admitted",
		feeds.check_admission("fine", "198.51.100.1").ok)
	_check("a listed account is refused",
		not feeds.check_admission("listed-account", "198.51.100.1").ok)
	_check("a listed address is refused",
		not feeds.check_admission("fine", "203.0.113.99").ok)
	_check("the upstream reason is passed on",
		feeds.check_admission("listed-account", "1.1.1.1")
			.error.message.contains("cheating"))

	# The chain: both have to say yes.
	upstream.refuse = "banned-upstream"
	_check("the chained source can still refuse",
		not feeds.check_admission("banned-upstream", "198.51.100.1").ok)
	upstream.refuse = ""
	_check("and admits when it has nothing to say",
		feeds.check_admission("anyone", "198.51.100.1").ok)

	feeds.show_upstream_reason = false
	_check("an upstream reason can be withheld from the player",
		not feeds.check_admission("listed-account", "1.1.1.1")
			.error.message.contains("cheating"))
	feeds.show_upstream_reason = true

	# A game module loading after boot -- a changelevel -- registers GameSpice Moderation
	# under the same name, and the registry is last-wins. Captured once at _ready,
	# the feeds were displaced from every admission after the first level change.
	var late := StubBanSource.new()
	GSRegistry.register(GSBanFeeds.BAN_SOURCE, late)
	await get_tree().process_frame
	_check("a source registered later does not displace the feeds",
		GSRegistry.get_service(GSBanFeeds.BAN_SOURCE) == feeds)
	_check("the feeds chain onto the newcomer",
		feeds.previous_source == late)
	late.refuse = "banned-late"
	_check("so the newcomer's bans are still enforced",
		not feeds.check_admission("banned-late", "198.51.100.1").ok)
	late.refuse = ""

	# The module unloading takes its registration with it; the feeds take the seam
	# back rather than leaving it empty while the next game loads.
	GSRegistry.unregister_instance(GSBanFeeds.BAN_SOURCE, feeds)
	await get_tree().process_frame
	_check("an emptied seam is taken back",
		GSRegistry.get_service(GSBanFeeds.BAN_SOURCE) == feeds)

	# Something that already chains to the feeds (the booking seam does) is left on
	# top: going over it again would make the chain a loop.
	var wrapper := StubBanSource.new()
	wrapper.previous_source = feeds
	GSRegistry.register(GSBanFeeds.BAN_SOURCE, wrapper)
	await get_tree().process_frame
	_check("a source that already chains to the feeds keeps the seam",
		GSRegistry.get_service(GSBanFeeds.BAN_SOURCE) == wrapper
			and feeds.previous_source != wrapper)
	GSRegistry.register(GSBanFeeds.BAN_SOURCE, feeds)
	_done()



func _test_anticheat() -> void:
	print("")
	_section("[anti-cheat]")

	_check("the detectors attached", anticheat.guard == guard)

	# The split that the whole design rests on.
	_check("speed is proof",
		GSAntiCheatEvent.is_impossible(GSAntiCheatEvent.SPEED))
	_check("aim analysis is not",
		GSAntiCheatEvent.is_suspicious(GSAntiCheatEvent.AIM_SNAP))
	_check("a single impossible event may be acted on",
		GSAntiCheatEvent.may_act_on_one(GSAntiCheatEvent.TIMING))
	_check("a single behavioural one may not",
		not GSAntiCheatEvent.may_act_on_one(GSAntiCheatEvent.TRIGGERBOT))

	var rule := _rule(&"t_speed", GSAntiCheatEvent.SPEED, 1)
	guard.policy.add(rule)
	guard._reindex()

	var session := GSClientSession.new()
	session.peer_id = 700
	session.userid = 700
	session.address = "203.0.113.70"
	session.display_name = "Runner"

	var subject := GSSecuritySubject.of_session(
		session, GSSecuritySubject.Scope.UID
	)

	anticheat.observe_move(session, Vector3.ZERO, Vector3(10, 0, 0), true, 0.1)
	_check("ordinary movement reports nothing",
		guard.ledger.for_subject(subject).is_empty())

	anticheat.observe_move(
		session, Vector3(1, 0, 0), Vector3(500, 0, 0), true, 0.1
	)
	# Not "== 1": the shipped cheat_movement rule watches the same event and
	# trips alongside the one this test added, which is correct and is what two
	# rules on one event are for.
	_check("impossible speed is reported",
		not guard.ledger.for_subject(subject).is_empty())

	# The reference simulation is the check that cannot be argued with: the
	# server re-runs the movement and compares.
	anticheat.movement_reference = func(
		_s: GSClientSession, from: Vector3, _v: Vector3, _c: Variant, _d: float
	) -> Vector3:
		return from

	var honest := GSClientSession.new()
	honest.peer_id = 701
	honest.userid = 701
	honest.address = "203.0.113.71"
	var honest_subject := GSSecuritySubject.of_session(
		honest, GSSecuritySubject.Scope.UID
	)

	anticheat.observe_move(honest, Vector3.ZERO, Vector3.ZERO, true, 0.1)
	anticheat.observe_move(honest, Vector3.ZERO, Vector3.ZERO, true, 0.1)
	_check("a client that matches the re-simulation is clean",
		guard.ledger.for_subject(honest_subject).is_empty())

	anticheat.observe_move(honest, Vector3(99, 0, 0), Vector3.ZERO, true, 0.1)
	_check("a client that does not is caught",
		not guard.ledger.for_subject(honest_subject).is_empty())
	anticheat.movement_reference = Callable()

	# Fire rate is arithmetic against the weapon's own cycle time.
	var shooter := GSClientSession.new()
	shooter.peer_id = 702
	shooter.userid = 702
	shooter.address = "203.0.113.72"
	var shooter_subject := GSSecuritySubject.of_session(
		shooter, GSSecuritySubject.Scope.UID
	)

	guard.policy.add(_rule(&"t_fire", GSAntiCheatEvent.FIRE_RATE, 1))
	guard._reindex()

	anticheat.observe_shot(shooter, &"rifle", 1.0)
	anticheat.observe_shot(shooter, &"rifle", 1.0)
	_check("firing faster than the weapon allows is caught",
		not guard.ledger.for_subject(shooter_subject).is_empty())

	# Its own dry run, separate from the guard's: an operator trusts chat rules
	# long before a movement threshold they have not measured.
	anticheat.config.dry_run = true
	var quiet := GSClientSession.new()
	quiet.peer_id = 703
	quiet.userid = 703
	quiet.address = "203.0.113.73"
	anticheat.observe_move(quiet, Vector3.ZERO, Vector3(999, 0, 0), true, 0.1)
	anticheat.observe_move(quiet, Vector3(9, 0, 0), Vector3(999, 0, 0), true, 0.1)
	_check("anti-cheat dry run reports nothing to the rules",
		guard.ledger.for_subject(GSSecuritySubject.of_session(
			quiet, GSSecuritySubject.Scope.UID)).is_empty())

	# Dry run is the path that logs a detection's detail, and some of that detail
	# is the client's own words: its build string. The log line an admin reads to
	# decide who cheated must not be writable by the person being judged.
	var saved_hashes := anticheat.config.accepted_build_hashes
	anticheat.config.accepted_build_hashes = PackedStringArray(["build-ok"])
	var logged: Array[String] = []
	var listen := func(rec: Dictionary) -> void:
		if str(rec.get("channel", "")) == GSAntiCheat.CHANNEL:
			logged.append(GSLog.format_line(rec))
	GSLog.signals().record.connect(listen)
	anticheat.observe_build(
		quiet, "evil\ninf security rule tripped rule=forged " + "x".repeat(4000)
	)
	GSLog.signals().record.disconnect(listen)
	anticheat.config.accepted_build_hashes = saved_hashes
	_check("a client's build string cannot forge a log line",
		logged.size() == 1 and not logged[0].contains("\n"))
	_check("nor make one a megabyte long",
		logged.size() == 1 and logged[0].length() < 400)
	anticheat.config.dry_run = false

	# The refusal that stops an operator banning a good player on one signal.
	var reckless := GSSecurityRule.of(
		&"t_reckless", GSAntiCheatEvent.AIM_SNAP, 1, 60.0
	)
	reckless.steps = [GSSecurityStep.of(GSSecurityAction.Kind.BAN, 0)]
	guard.policy.add(reckless)
	guard._reindex()
	anticheat._audit_rules()
	_check("a rule banning on one behavioural signal is refused",
		not guard.policy.find(&"t_reckless").enabled)

	var sane := GSSecurityRule.of(
		&"t_sane", GSAntiCheatEvent.AIM_SNAP, 20, 300.0
	)
	sane.steps = [GSSecurityStep.of(GSSecurityAction.Kind.WARN)]
	guard.policy.add(sane)
	guard._reindex()
	anticheat._audit_rules()
	_check("a behavioural rule that only warns is left alone",
		guard.policy.find(&"t_sane").enabled)

	# Every shipped behavioural rule must obey the same standard.
	var shipped := GSSecurityPolicy.defaults()
	var offenders := PackedStringArray()
	for r in shipped.enabled_rules():
		if not GSAntiCheatEvent.is_suspicious(r.event):
			continue
		for step in (r.steps if not r.steps.is_empty()
				else [GSSecurityStep.of(r.action, r.duration_sec)]):
			if step.action != GSSecurityAction.Kind.WARN \
					and step.action != GSSecurityAction.Kind.NONE:
				offenders.append(String(r.id))
	_check("no shipped behavioural rule ever punishes",
		offenders.is_empty())
	_done()



func _test_without_moderation() -> void:
	print("")
	_section("[without a moderation store]")

	# The promise of the fallback: with no GameSpice Moderation a gag is still felt, it just does not survive a reconnect.
	# Refusing to act without it would make this addon conditional on another optional one.
	var session := GSClientSession.new()
	session.peer_id = 800
	session.userid = 800
	session.address = "203.0.113.80"
	session.display_name = "Nobody"

	var gagged := GSSecurityAction.apply(
		GSSecurityAction.Kind.GAG, "uid:fallback", 120, "test", "suite",
		null, server, session
	)
	_check("a gag applies with no store at all", gagged.ok)
	_check("and the session feels it", session.gagged)
	_check("and it expires", session.mute_expires_at > 0)
	_check("and it says it was session-only",
		str(gagged.value).contains("session only"))

	session.unsilence()
	var silenced := GSSecurityAction.apply(
		GSSecurityAction.Kind.SILENCE, "uid:fallback", 60, "test", "suite",
		null, server, session
	)
	_check("silence covers both", silenced.ok and session.gagged and session.muted)

	# With nothing to act on and nothing to record, it fails rather than
	# claiming success — an action that quietly did nothing is the worst answer.
	var nothing := GSSecurityAction.apply(
		GSSecurityAction.Kind.GAG, "uid:absent", 60, "test", "suite",
		null, server, null
	)
	_check("no store and no session is an honest failure", not nothing.ok)

	# Loopback is never acted on, however a rule is written, and that is not an
	# error: the first thing a guard must not do is lock the operator out.
	var loopback := GSSecurityAction.apply(
		GSSecurityAction.Kind.BAN, "ip:127.0.0.1", 0, "test", "suite",
		null, server, null
	)
	_check("loopback is refused as a no-op, not as a failure",
		loopback.ok and str(loopback.value).contains("exempt"))

	# ...and with the real store present, the same call records durably.
	var mod := GSRegistry.get_service(&"gs_moderation")
	_check("the real moderation store is installed for this suite", mod != null)

	if mod == null:
		return

	var durable := GSSecurityAction.apply(
		GSSecurityAction.Kind.GAG, "uid:durable-test", 60, "auto", "suite",
		mod, server, null
	)
	_check("with a store, it records with no session at all", durable.ok)
	_check("and gs-moderation holds the record",
		mod.call("is_gagged_key", "uid:durable-test"))

	# The guard attaches BEFORE the store exists (the game's module loads after the server boots), and latching that null
	# made every punishment quietly die with the connection. Asserted by taking the cached answer away rather than
	# re-attaching, because what broke was the latch and not the lookup.
	guard.moderation = null
	_check("the store is found again when it was not there at attach",
		guard.moderation_store() == mod)
	_check("and the guard reports the one that is actually in force",
		bool(guard.describe()["moderation"]))
	_check("which is what sec_status says too",
		_run("sec_status").contains("durable"))
	_done()



func _test_console() -> void:
	print("")
	_section("[console]")

	for name in [
		"sec_status", "sec_rules", "sec_rule", "sec_why", "sec_forget",
		"sec_enable", "sec_disable", "sec_reload", "sec_log", "sec_dump",
		"sec_test", "sec_bans", "sec_bans_refresh", "sec_bans_check",
		"sec_ac_status", "sec_ac_dryrun",
	]:
		_check("%s is registered" % name,
			server.console.find_command(name) != null)

	_check("sec_status reports", _run("sec_status").contains("[security]"))
	_check("sec_rules lists the shipped rules",
		_run("sec_rules").contains("chat_flood"))

	_run("sec_disable chat_flood")
	_check("a rule can be turned off from the console",
		not guard.policy.find(&"chat_flood").enabled)
	_run("sec_enable chat_flood")
	_check("and back on", guard.policy.find(&"chat_flood").enabled)

	_check("sec_why says so when it knows nothing",
		_run("sec_why nobody-at-all").contains("no record"))
	_check("sec_why finds a subject it does know",
		_run("sec_why climber").contains("t_ladder"))

	_check("sec_bans reports the feeds", _run("sec_bans").contains("listed"))
	_check("sec_bans_check finds a listed account",
		_run("sec_bans_check listed-account").contains("cheating"))
	_check("sec_ac_status reports the peaks",
		_run("sec_ac_status").contains("peaks seen"))
	_done()


## A ban source with GameSpice Moderation's shape and none of its identifiers.
class StubBanSource extends RefCounted:
	var refuse: String = ""
	var previous_source: Object = null

	func check_admission(uid: String, _address: String) -> GSResult:
		if refuse != "" and uid == refuse:
			return GSResult.fail(GSError.CODE_FORBIDDEN, "Refused upstream.")
		return GSResult.success(true)
