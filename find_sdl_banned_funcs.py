# IDAPython script to check for banned SDL functions
#
# Created: July 15th, 2016
# Author: Paul Larivere - @Dcept905
# Banned function list source: https://msdn.microsoft.com/en-us/library/bb288454.aspx
# To run select File -> Script File in IDA and browse to this script file location
# GitHub repo: https://github.com/0xC0D1F1ED/IDA_Find_SDL_Banned_Functions

from idaapi import *

banned = (["strcpy", "strcpyA", "strcpyW", "wcscpy", "_tcscpy", "_mbscpy", "StrCpy", "StrCpy", "StrCpyW", "lstrcpy", 		# Banned string copy functions
	"lstrcpyA", "lstrcpyW", "_tccpy", "_mbccpy", "_ftcscpy", "strncpy", "wcsncpy", "_tcsncpy", "_mbsncpy", "_mbsnbcpy", 
	"StrCpyN", "StrCpyNA", "StrCpyNW", "StrNCpy", "strcpynA", "StrNCpyA", "StrNCpyW", "lstrcpyn", "lstrcpynA", "lstrcpynW", 
	"strcat", "strcatA", "strcatW", "wcscat", "_tcscat", "_mbscat", "StrCat", "StrCatA", "StrCatW", "lstrcat", "lstrcatA", 	# Banned string concatenation functions
	"lstrcatW", "StrCatBuff", "StrCatBuffA", "StrCatBuffW", "StrCatChainW", "_tccat", "_mbccat", "_ftcscat", "strncat", 
	"wcsncat", "_tcsncat", "_mbsncat", "_mbsnbcat", "StrCatN", "StrCatNA", "StrCatNW", "StrNCat", "StrNCatA", "StrNCatW", 
	"lstrncat", "lstrcatnA", "lstrcatnW", "lstrcatn",
	"sprintfW", "sprintfA", "wsprintf", "wsprintfW", "wsprintfA", "sprintf", "swprintf", "_stprintf", "wvsprintf", 		# Banned sprintf functions
	"wvsprintfA", "wvsprintfW", "vsprintf", "_vstprintf", "vswprintf", "wnsprintf", "wnsprintfA", "wnsprintfW", 
	"_snwprintf", "snprintf", "sntprintf", "_vsnprintf", "vsnprintf", "_vsnwprintf", "_vsntprintf", "wvnsprintf", 
	"wvnsprintfA", "wvnsprintfW",
	"_snwprintf", "_snprintf", "_sntprintf", "nsprintf", 									# Banned "n" sprintf functions
	"wvsprintf", "wvsprintfA", "wvsprintfW", "vsprintf", "_vstprintf", "vswprintf",						# Banned variable argument sprintf functions
	"_vsnprintf", "_vsnwprintf", "_vsntprintf", "wvnsprintf", "wvnsprintfA", "wvnsprintfW",					# Banned variable argument "n" sprintf functions
	"strncpy", "wcsncpy", "_tcsncpy", "_mbsncpy", "_mbsnbcpy", "StrCpyN", "StrCpyNA", "StrCpyNW", "StrNCpy", "strcpynA", 	# Banned "n" string copy functions
	"StrNCpyA", "StrNCpyW", "lstrcpyn", "lstrcpynA", "lstrcpynW", "_fstrncpy",
	"strncat", "wcsncat", "_tcsncat", "_mbsncat", "_mbsnbcat", "StrCatN", "StrCatNA", "StrCatNW", "StrNCat", "StrNCatA", 	# Banned "n" string concatenation functions
	"StrNCatW", "lstrncat", "lstrcatnA", "lstrcatnW", "lstrcatn", "_fstrncat",
	"strtok", "_tcstok", "wcstok", "_mbstok",										# Banned string tokenizing functions
	"makepath", "_tmakepath", "_makepath", "_wmakepath",									# Banned Makepath functions
	"_splitpath", "_tsplitpath", "_wsplitpath",										# Banned Splitpath functions
	"scanf", "wscanf", "_tscanf", "sscanf", "swscanf", "_stscanf",								# Banned scanf functions
	"snscanf", "snwscanf", "_sntscanf",											# Banned "n" scanf functions
	"_itoa", "_itow", "_i64toa", "_i64tow", "_ui64toa", "_ui64tot", "_ui64tow", "_ultoa", "_ultot", "_ultow",		# Banned numeric conversion functions
	"gets", "_getts", "_gettws",												# Banned gets functions
	"IsBadWritePtr", "IsBadHugeWritePtr", "IsBadReadPtr", "IsBadHugeReadPtr", "IsBadCodePtr", "IsBadStringPtr",		# Banned IsBad functions
	"CharToOem", "CharToOemA", "CharToOemW", "OemToChar", "OemToCharA", "OemToCharW", "CharToOemBuffA", "CharToOemBuffW",	# Banned OEM conversion functions
	"alloca", "_alloca",													# Banned stack dynamic memory allocation functions
	"strlen", "wcslen", "_mbslen", "_mbstrlen", "StrLen", "lstrlen",							# Banned string length functions
	"memcpy", "RtlCopyMemory", "CopyMemory", "wmemcpy",									# Banned memory copy functions
	"ChangeWindowMessageFilter"])												# Banned window messaging functions


funcs = Functions()
Message("\nBeginning search for banned functions.\n")
foundList = []
for f in funcs:
	for b in banned:
		#if (Name(f).upper().endswith(b.upper())):		# using Upper here was force of habbit but might be stupid. possible for duplicates ie: strcat and StrCat
		if (Name(f).endswith(b)):
			if Name(f) not in foundList:			# really terrible and ineffecient way to perform de-duplication
				foundList.append(Name(f))
				Message("Potential function: %s located. Name: %s\n" % (b, Name(f)))
				items = FuncItems(f)			# produce a list of xrefs to this function
				for item in items:
					for xref in XrefsTo(item, 0):
						if xref.type == fl_CN or xref.type == fl_CF:
							Message("* %s is called from %s at %s\n" % (Name(f), GetFunctionName(xref.frm), hex(xref.frm)))
							#Message("type: %s, typename: %s, from: %s, at: %s\n" % (xref.type, XrefTypeName(xref.type), Name(xref.frm), hex(xref.frm)))

Message("Search complete.\n")
