import binaryninja
import yara

def yara_scan(bv,function):
	show_message_box("Do Nothing", "Congratulations! You have successfully done nothing.\n\n" +
					 "Pat yourself on the back.", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

PluginCommand.register_for_address("[YARA] Scan with yara rule...", "Scan file with single yara rule", do_nothing)
