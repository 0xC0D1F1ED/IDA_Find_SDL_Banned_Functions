# find_sdl_banned_funcs

Find SDL Banned Functions is an IDAPython script written to find functions from the MS Security Development Lifecycle (SDL) Banned Function Calls list published at: https://msdn.microsoft.com/en-us/library/bb288454.aspx

I wrote this script quickly to find these functions because other scripts that have been released didn't have a comprehensive list of banned functions and/or failed to find functions (ie: could find memcpy, but not _memcpy).  If you find any bugs or have any comments/questions/requests I can be contacted on Twitter at @Dcept905.

