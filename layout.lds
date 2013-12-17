SECTIONS
{
	.khook : {
		__khook_start = . ;
		*(.khook)
		__khook_finish = . ;
	}
}
