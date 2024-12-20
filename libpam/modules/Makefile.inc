PAMDIR=		${.CURDIR}/../../../openpam

MK_INSTALLLIB=	no

CFLAGS+= -I${PAMDIR}/include -I${.CURDIR}/../../libpam

SHLIB_NAME?=	${LIB}.so.${SHLIB_MAJOR}
LIBADD+=	pam

.include "../Makefile.inc"
