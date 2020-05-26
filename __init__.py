from binaryninja import *
import yara

def get_yara_rule_path():
	return get_open_filename_input("Open YARA rule", "YARA rules (*.yar *.yara)")

def get_markdown_result(matches):
	entry_fmt = "| {} | {} | {} |\n"
	md_text = """ # YARA - Scan results

| Rule Name | Function | Strings offsets |
|-----------|----------|-----------------|
"""
	for m in matches:
		rule = m['rule']
		func = 'unknown'
		if 'func' in m:
			func = m['func']
		
		# 'strings': [(81L, '$a', 'abc'), (141L, '$b', 'def')]
		s = " ".join(['["{}"](binaryninja://?expr=0x{:x})'.format(s[2].decode('utf-8'), s[0]) for s in m['strings']])
		md_text += entry_fmt.format(rule, func, s)
	return md_text

def plugin_search_file(bv):
	matches = []
	
	def yara_callback(data):
		"""
			{
			'tags': ['foo', 'bar'],
			'matches': True,
			'namespace': 'default',
			'rule': 'my_rule',
			'meta': {},
			'strings': [(81L, '$a', 'abc'), (141L, '$b', 'def')]
			}
		"""
		if data['matches']:
			matches.append(data)
		yara.CALLBACK_CONTINUE

	yara_path = get_yara_rule_path()
	
	# user closed message prompt
	if yara_path is None:
		return

	try:
		rules = yara.compile(filepath=yara_path.decode('utf-8'))
		rules.match(bv.file.original_filename, callback=yara_callback)

	except Exception as e:
		log_error("[YARA] Exception: {}".format(str(e)))
		show_message_box("Error", "Check logs for details", icon=MessageBoxIcon.ErrorIcon)

	if len(matches) > 0:
		bv.show_markdown_report("YARA", get_markdown_result(matches))
	else:
		log_info("[YARA] No matches")

def plugin_search_functions(bv):
	show_message_box("Not implemented", "This feature is not implemented yet")
	# TODO

PluginCommand.register("[YARA] Scan file with yara rule...", "Scan file with yara rule", plugin_search_file)
# PluginCommand.register('[YARA] Scan functions with yara rule...', "Scan all functions with yara rules (might be slower)", plugin_search_functions)
