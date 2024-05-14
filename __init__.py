from binaryninja import *
import yara
import pefile

def get_yara_rule_path():
	return get_open_filename_input("Open YARA rule", "YARA rules (*.yar *.yara)")

def get_markdown_result(matches, bv):
	entry_fmt = "| {} | {} |\n"
	md_text = """ # YARA - Scan results

| Rule Name |   Matches   |
|-----------|-------------|
"""
	for m in matches:
		rule = m['rule']
		# Updated 1) for YARA 4.2.3 and 2)to show bytes or strings depending upon hit 3) link to location in code
		s = "  ".join(['["{}"](binaryninja://?expr=0x{:x})'.format(instance.matched_data.decode('ascii') if all(32 <= b < 127 for b in instance.matched_data) else ' '.join(format(byte, '02X') for byte in instance.matched_data), bv.get_address_for_data_offset(instance.offset)) for string in m['strings'] for instance in string.instances])
		md_text += entry_fmt.format(rule, s)
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
		rules = yara.compile(filepath=yara_path)
		rules.match(bv.file.original_filename, callback=yara_callback)

	except Exception as e:
		log_error("[YARA] Exception: {}".format(str(e)))
		show_message_box("Error", "Check logs for details", icon=MessageBoxIcon.ErrorIcon)

	if len(matches) > 0:
		bv.show_markdown_report("YARA", get_markdown_result(matches, bv))
	else:
		log_info("[YARA] No matches")

def plugin_search_functions(bv):
	show_message_box("Not implemented", "This feature is not implemented yet")
	# TODO

PluginCommand.register("[YARA] Scan file with yara rule...", "Scan file with yara rule", plugin_search_file)
# PluginCommand.register('[YARA] Scan functions with yara rule...', "Scan all functions with yara rules (might be slower)", plugin_search_functions)
