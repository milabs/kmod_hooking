## About


This module provides mechanism that allows to hook kernel functions using exception tables.

## Usage

Given the kernel function `X` which has prototype `typeof(X)` let's see how to hook it:

1. Use `DECLARE_KHOOK(X)` macro to declare the hook
2. Write hook's body using `khook_X` function name and `typeof(X)` as a prototype
3. Use `KHOOK_ORIGIN(X, args)` macro as a wrapper around the `X` function call
4. Protect hook's body with `KHOOK_USAGE_INC(X)` and `KHOOK_USAGE_DEC(X)`


## Example

```
#include <linux/fs.h> // inode_permission() prototype lives here

DECLARE_KHOOK(inode_permission);
int khook_inode_permission(struct inode * inode, int mode)
{
	int result;

	KHOOK_USAGE_INC(inode_permission);

	debug("%s(%pK,%08x) [%s]\n", __func__, inode, mode, current->comm);

	result = KHOOK_ORIGIN(inode_permission, inode, mode);

	debug("%s(%pK,%08x) [%s] = %d\n", __func__, inode, mode, current->comm, result);

	KHOOK_USAGE_DEC(inode_permission);

	return result;
}
```

## Credits

Written by Ilya V. Matveychikov <i.matveychikov@milabs.ru>, distributed under GPL
