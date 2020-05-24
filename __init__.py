from binaryninja.plugin import PluginCommand
import yara

def yarasearch(rule_locations, offset):
	rules = yara.compile(filepaths=rule_location, includes=True)

def plugin_search_file(bv):
	show_message_box("Do Nothing", "Congratulations! You have successfully done nothing.\n\n" +
					 "Pat yourself on the back.", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

PluginCommand.register("[YARA] Scan with yara rule...", "Scan file with single yara rule", yara_scan)
