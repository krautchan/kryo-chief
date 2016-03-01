#ifndef CONFIG_H_
#define CONFIG_H_

/* Shared configuration */

#define CONFIG_PREALLOC_FILES	16
#define CONFIG_RC4_DROP			4096

/* Server configuration */

#define CONFIG_RSA_KSIZE		1024
#define CONFIG_PREGEN_KEYS		128
#define CONFIG_REGEN_KEYS		96
#define CONFIG_KEYGEN_SLEEP		60
#define CONFIG_KEYTAB_SIZE		128
#define CONFIG_KEYDIR			"etc/keystore"
#define CONFIG_KEYFILE_EXT		".key"

/* Client configuration */

#define CONFIG_CRYPTED_EXT		".enc"
#define CONFIG_CRYPTDIR			"local/share/Steam"

#endif
