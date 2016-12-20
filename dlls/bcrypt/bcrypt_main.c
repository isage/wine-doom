/*
 * Copyright 2009 Henri Verbeet for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#include "config.h"
#include "wine/port.h"

#include <stdarg.h>
#ifdef HAVE_COMMONCRYPTO_COMMONDIGEST_H
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#elif defined(SONAME_LIBGCRYPT)
#include <gcrypt.h>
#elif defined(SONAME_LIBGNUTLS)
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "ntsecapi.h"
#include "bcrypt.h"

#include "wine/debug.h"
#include "wine/library.h"
#include "wine/unicode.h"

WINE_DEFAULT_DEBUG_CHANNEL(bcrypt);

static HINSTANCE instance;

#if defined(SONAME_LIBGCRYPT) && !defined(HAVE_COMMONCRYPTO_COMMONDIGEST_H)
WINE_DECLARE_DEBUG_CHANNEL(winediag);

static void *libgcrypt_handle;
#define MAKE_FUNCPTR(f) static typeof(f) * p##f
MAKE_FUNCPTR(gcry_check_version);
MAKE_FUNCPTR(gcry_set_log_handler);
MAKE_FUNCPTR(gcry_control);

MAKE_FUNCPTR(gcry_md_open);
MAKE_FUNCPTR(gcry_md_close);
MAKE_FUNCPTR(gcry_md_copy);
MAKE_FUNCPTR(gcry_md_setkey);
MAKE_FUNCPTR(gcry_md_write);
MAKE_FUNCPTR(gcry_md_read);

MAKE_FUNCPTR(gcry_md_ctl);
MAKE_FUNCPTR(gcry_md_debug);

MAKE_FUNCPTR(gcry_cipher_open);
MAKE_FUNCPTR(gcry_cipher_close);
MAKE_FUNCPTR(gcry_cipher_encrypt);
MAKE_FUNCPTR(gcry_cipher_decrypt);
MAKE_FUNCPTR(gcry_cipher_setiv);
MAKE_FUNCPTR(gcry_cipher_setkey);

MAKE_FUNCPTR(gcry_strerror);
MAKE_FUNCPTR(gcry_strsource);
#undef MAKE_FUNCPTR

static void gcrypt_log( void* opaque, int level, const char *msg, va_list arg_ptr)
{
    //todo: format message
    TRACE( "<%d> %s", level, msg );
}

static BOOL gcrypt_initialize(void)
{
    if (!(libgcrypt_handle = wine_dlopen( SONAME_LIBGCRYPT, RTLD_NOW, NULL, 0 )))
    {
        ERR_(winediag)( "failed to load libgcrypt, no support for crypto hashes\n" );
        return FALSE;
    }

#define LOAD_FUNCPTR(f) \
    if (!(p##f = wine_dlsym( libgcrypt_handle, #f, NULL, 0 ))) \
    { \
        ERR( "failed to load %s\n", #f ); \
        goto fail; \
    }

    LOAD_FUNCPTR(gcry_check_version)
    LOAD_FUNCPTR(gcry_set_log_handler)
    LOAD_FUNCPTR(gcry_control)

    LOAD_FUNCPTR(gcry_md_open);
    LOAD_FUNCPTR(gcry_md_close);
    LOAD_FUNCPTR(gcry_md_copy);
    LOAD_FUNCPTR(gcry_md_setkey);
    LOAD_FUNCPTR(gcry_md_write);
    LOAD_FUNCPTR(gcry_md_read);


    LOAD_FUNCPTR(gcry_md_ctl);
    LOAD_FUNCPTR(gcry_md_debug);

    LOAD_FUNCPTR(gcry_cipher_open);
    LOAD_FUNCPTR(gcry_cipher_close);
    LOAD_FUNCPTR(gcry_cipher_encrypt);
    LOAD_FUNCPTR(gcry_cipher_decrypt);
    LOAD_FUNCPTR(gcry_cipher_setiv);
    LOAD_FUNCPTR(gcry_cipher_setkey);

    LOAD_FUNCPTR(gcry_strerror);
    LOAD_FUNCPTR(gcry_strsource);
#undef LOAD_FUNCPTR

    if (!pgcry_check_version (GCRYPT_VERSION))
    {
        ERR( "gcrypt version mismatch\n");
        goto fail;
    }
    pgcry_control(GCRYCTL_DISABLE_SECMEM);
    if (TRACE_ON( bcrypt ))
    {
        pgcry_control(GCRYCTL_SET_VERBOSITY, 4 );
        pgcry_set_log_handler( gcrypt_log, NULL );
    }

    return TRUE;

fail:
    wine_dlclose( libgcrypt_handle, NULL, 0 );
    libgcrypt_handle = NULL;
    return FALSE;
}

static void gcrypt_uninitialize(void)
{
    wine_dlclose( libgcrypt_handle, NULL, 0 );
    libgcrypt_handle = NULL;
}
#elif defined(HAVE_GNUTLS_HASH) && !defined(HAVE_COMMONCRYPTO_COMMONDIGEST_H)
WINE_DECLARE_DEBUG_CHANNEL(winediag);

static void *libgnutls_handle;
#define MAKE_FUNCPTR(f) static typeof(f) * p##f
MAKE_FUNCPTR(gnutls_global_deinit);
MAKE_FUNCPTR(gnutls_global_init);
MAKE_FUNCPTR(gnutls_global_set_log_function);
MAKE_FUNCPTR(gnutls_global_set_log_level);
MAKE_FUNCPTR(gnutls_hash);
MAKE_FUNCPTR(gnutls_hash_deinit);
MAKE_FUNCPTR(gnutls_hash_init);
MAKE_FUNCPTR(gnutls_hmac);
MAKE_FUNCPTR(gnutls_hmac_deinit);
MAKE_FUNCPTR(gnutls_hmac_init);
MAKE_FUNCPTR(gnutls_perror);
#undef MAKE_FUNCPTR

static void gnutls_log( int level, const char *msg )
{
    TRACE( "<%d> %s", level, msg );
}

static BOOL gnutls_initialize(void)
{
    int ret;

    if (!(libgnutls_handle = wine_dlopen( SONAME_LIBGNUTLS, RTLD_NOW, NULL, 0 )))
    {
        ERR_(winediag)( "failed to load libgnutls, no support for crypto hashes\n" );
        return FALSE;
    }

#define LOAD_FUNCPTR(f) \
    if (!(p##f = wine_dlsym( libgnutls_handle, #f, NULL, 0 ))) \
    { \
        ERR( "failed to load %s\n", #f ); \
        goto fail; \
    }

    LOAD_FUNCPTR(gnutls_global_deinit)
    LOAD_FUNCPTR(gnutls_global_init)
    LOAD_FUNCPTR(gnutls_global_set_log_function)
    LOAD_FUNCPTR(gnutls_global_set_log_level)
    LOAD_FUNCPTR(gnutls_hash);
    LOAD_FUNCPTR(gnutls_hash_deinit);
    LOAD_FUNCPTR(gnutls_hash_init);
    LOAD_FUNCPTR(gnutls_hmac);
    LOAD_FUNCPTR(gnutls_hmac_deinit);
    LOAD_FUNCPTR(gnutls_hmac_init);
    LOAD_FUNCPTR(gnutls_perror)
#undef LOAD_FUNCPTR

    if ((ret = pgnutls_global_init()) != GNUTLS_E_SUCCESS)
    {
        pgnutls_perror( ret );
        goto fail;
    }

    if (TRACE_ON( bcrypt ))
    {
        pgnutls_global_set_log_level( 4 );
        pgnutls_global_set_log_function( gnutls_log );
    }

    return TRUE;

fail:
    wine_dlclose( libgnutls_handle, NULL, 0 );
    libgnutls_handle = NULL;
    return FALSE;
}

static void gnutls_uninitialize(void)
{
    pgnutls_global_deinit();
    wine_dlclose( libgnutls_handle, NULL, 0 );
    libgnutls_handle = NULL;
}

#endif /* HAVE_GNUTLS_HASH && !HAVE_COMMONCRYPTO_COMMONDIGEST_H */

NTSTATUS WINAPI BCryptEnumAlgorithms(ULONG dwAlgOperations, ULONG *pAlgCount,
                                     BCRYPT_ALGORITHM_IDENTIFIER **ppAlgList, ULONG dwFlags)
{
    FIXME("%08x, %p, %p, %08x - stub\n", dwAlgOperations, pAlgCount, ppAlgList, dwFlags);

    *ppAlgList=NULL;
    *pAlgCount=0;

    return STATUS_NOT_IMPLEMENTED;
}

#define MAGIC_ALG  (('A' << 24) | ('L' << 16) | ('G' << 8) | '0')
#define MAGIC_HASH (('H' << 24) | ('A' << 16) | ('S' << 8) | 'H')
#define MAGIC_KEY  (('K' << 24) | ('E' << 16) | ('Y' << 8) | '0')
struct object
{
    ULONG magic;
};

enum alg_id
{
    ALG_ID_MD5,
    ALG_ID_RNG,
    ALG_ID_SHA1,
    ALG_ID_SHA256,
    ALG_ID_SHA384,
    ALG_ID_SHA512,
    ALG_ID_AES
};

static const struct {
    ULONG hash_length;
    const WCHAR *alg_name;
} alg_props[] = {
    /* ALG_ID_MD5    */ { 16, BCRYPT_MD5_ALGORITHM },
    /* ALG_ID_RNG    */ {  0, BCRYPT_RNG_ALGORITHM },
    /* ALG_ID_SHA1   */ { 20, BCRYPT_SHA1_ALGORITHM },
    /* ALG_ID_SHA256 */ { 32, BCRYPT_SHA256_ALGORITHM },
    /* ALG_ID_SHA384 */ { 48, BCRYPT_SHA384_ALGORITHM },
    /* ALG_ID_SHA512 */ { 64, BCRYPT_SHA512_ALGORITHM }
};

struct algorithm
{
    struct object hdr;
    enum alg_id   id;
    BOOL hmac;
};

NTSTATUS WINAPI BCryptGenRandom(BCRYPT_ALG_HANDLE handle, UCHAR *buffer, ULONG count, ULONG flags)
{
    const DWORD supported_flags = BCRYPT_USE_SYSTEM_PREFERRED_RNG;
    struct algorithm *algorithm = handle;

    TRACE("%p, %p, %u, %08x - semi-stub\n", handle, buffer, count, flags);

    if (!algorithm)
    {
        /* It's valid to call without an algorithm if BCRYPT_USE_SYSTEM_PREFERRED_RNG
         * is set. In this case the preferred system RNG is used.
         */
        if (!(flags & BCRYPT_USE_SYSTEM_PREFERRED_RNG))
            return STATUS_INVALID_HANDLE;
    }
    else if (algorithm->hdr.magic != MAGIC_ALG || algorithm->id != ALG_ID_RNG)
        return STATUS_INVALID_HANDLE;

    if (!buffer)
        return STATUS_INVALID_PARAMETER;

    if (flags & ~supported_flags)
        FIXME("unsupported flags %08x\n", flags & ~supported_flags);

    if (algorithm)
        FIXME("ignoring selected algorithm\n");

    /* When zero bytes are requested the function returns success too. */
    if (!count)
        return STATUS_SUCCESS;

    if (algorithm || (flags & BCRYPT_USE_SYSTEM_PREFERRED_RNG))
    {
        if (RtlGenRandom(buffer, count))
            return STATUS_SUCCESS;
    }

    FIXME("called with unsupported parameters, returning error\n");
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptOpenAlgorithmProvider( BCRYPT_ALG_HANDLE *handle, LPCWSTR id, LPCWSTR implementation, DWORD flags )
{
    struct algorithm *alg;
    enum alg_id alg_id;

    const DWORD supported_flags = BCRYPT_ALG_HANDLE_HMAC_FLAG;

    TRACE( "%p, %s, %s, %08x\n", handle, wine_dbgstr_w(id), wine_dbgstr_w(implementation), flags );

    if (!handle || !id) return STATUS_INVALID_PARAMETER;
    if (flags & ~supported_flags)
    {
        FIXME( "unsupported flags %08x\n", flags & ~supported_flags);
        return STATUS_NOT_IMPLEMENTED;
    }

    if (!strcmpW( id, BCRYPT_SHA1_ALGORITHM )) alg_id = ALG_ID_SHA1;
    else if (!strcmpW( id, BCRYPT_MD5_ALGORITHM )) alg_id = ALG_ID_MD5;
    else if (!strcmpW( id, BCRYPT_RNG_ALGORITHM )) alg_id = ALG_ID_RNG;
    else if (!strcmpW( id, BCRYPT_SHA256_ALGORITHM )) alg_id = ALG_ID_SHA256;
    else if (!strcmpW( id, BCRYPT_SHA384_ALGORITHM )) alg_id = ALG_ID_SHA384;
    else if (!strcmpW( id, BCRYPT_SHA512_ALGORITHM )) alg_id = ALG_ID_SHA512;
    else if (!strcmpW( id, BCRYPT_AES_ALGORITHM )) alg_id = ALG_ID_AES;
    else
    {
        FIXME( "algorithm %s not supported\n", debugstr_w(id) );
        return STATUS_NOT_IMPLEMENTED;
    }
    if (implementation && strcmpW( implementation, MS_PRIMITIVE_PROVIDER ))
    {
        FIXME( "implementation %s not supported\n", debugstr_w(implementation) );
        return STATUS_NOT_IMPLEMENTED;
    }

    if (!(alg = HeapAlloc( GetProcessHeap(), 0, sizeof(*alg) ))) return STATUS_NO_MEMORY;
    alg->hdr.magic = MAGIC_ALG;
    alg->id        = alg_id;
    alg->hmac      = flags & BCRYPT_ALG_HANDLE_HMAC_FLAG;

    *handle = alg;
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptCloseAlgorithmProvider( BCRYPT_ALG_HANDLE handle, DWORD flags )
{
    struct algorithm *alg = handle;

    TRACE( "%p, %08x\n", handle, flags );

    if (!alg || alg->hdr.magic != MAGIC_ALG) return STATUS_INVALID_HANDLE;
    HeapFree( GetProcessHeap(), 0, alg );
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptGetFipsAlgorithmMode(BOOLEAN *enabled)
{
    FIXME("%p - semi-stub\n", enabled);

    if (!enabled)
        return STATUS_INVALID_PARAMETER;

    *enabled = FALSE;
    return STATUS_SUCCESS;
}

#ifdef HAVE_COMMONCRYPTO_COMMONDIGEST_H
struct hash
{
    struct object hdr;
    enum alg_id   alg_id;
    BOOL hmac;
    union
    {
        CC_MD5_CTX    md5_ctx;
        CC_SHA1_CTX   sha1_ctx;
        CC_SHA256_CTX sha256_ctx;
        CC_SHA512_CTX sha512_ctx;
        CCHmacContext hmac_ctx;
    } u;
};

static NTSTATUS hash_init( struct hash *hash )
{
    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        CC_MD5_Init( &hash->u.md5_ctx );
        break;

    case ALG_ID_SHA1:
        CC_SHA1_Init( &hash->u.sha1_ctx );
        break;

    case ALG_ID_SHA256:
        CC_SHA256_Init( &hash->u.sha256_ctx );
        break;

    case ALG_ID_SHA384:
        CC_SHA384_Init( &hash->u.sha512_ctx );
        break;

    case ALG_ID_SHA512:
        CC_SHA512_Init( &hash->u.sha512_ctx );
        break;

    default:
        ERR( "unhandled id %u\n", hash->alg_id );
        return STATUS_NOT_IMPLEMENTED;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS hmac_init( struct hash *hash, UCHAR *key, ULONG key_size )
{
    CCHmacAlgorithm cc_algorithm;
    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        cc_algorithm = kCCHmacAlgMD5;
        break;

    case ALG_ID_SHA1:
        cc_algorithm = kCCHmacAlgSHA1;
        break;

    case ALG_ID_SHA256:
        cc_algorithm = kCCHmacAlgSHA256;
        break;

    case ALG_ID_SHA384:
        cc_algorithm = kCCHmacAlgSHA384;
        break;

    case ALG_ID_SHA512:
        cc_algorithm = kCCHmacAlgSHA512;
        break;

    default:
        ERR( "unhandled id %u\n", hash->alg_id );
        return STATUS_NOT_IMPLEMENTED;
    }

    CCHmacInit( &hash->u.hmac_ctx, cc_algorithm, key, key_size );
    return STATUS_SUCCESS;
}


static NTSTATUS hash_update( struct hash *hash, UCHAR *input, ULONG size )
{
    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        CC_MD5_Update( &hash->u.md5_ctx, input, size );
        break;

    case ALG_ID_SHA1:
        CC_SHA1_Update( &hash->u.sha1_ctx, input, size );
        break;

    case ALG_ID_SHA256:
        CC_SHA256_Update( &hash->u.sha256_ctx, input, size );
        break;

    case ALG_ID_SHA384:
        CC_SHA384_Update( &hash->u.sha512_ctx, input, size );
        break;

    case ALG_ID_SHA512:
        CC_SHA512_Update( &hash->u.sha512_ctx, input, size );
        break;

    default:
        ERR( "unhandled id %u\n", hash->alg_id );
        return STATUS_NOT_IMPLEMENTED;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS hmac_update( struct hash *hash, UCHAR *input, ULONG size )
{
    CCHmacUpdate( &hash->u.hmac_ctx, input, size );
    return STATUS_SUCCESS;
}

static NTSTATUS hash_finish( struct hash *hash, UCHAR *output, ULONG size )
{
    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        CC_MD5_Final( output, &hash->u.md5_ctx );
        break;

    case ALG_ID_SHA1:
        CC_SHA1_Final( output, &hash->u.sha1_ctx );
        break;

    case ALG_ID_SHA256:
        CC_SHA256_Final( output, &hash->u.sha256_ctx );
        break;

    case ALG_ID_SHA384:
        CC_SHA384_Final( output, &hash->u.sha512_ctx );
        break;

    case ALG_ID_SHA512:
        CC_SHA512_Final( output, &hash->u.sha512_ctx );
        break;

    default:
        ERR( "unhandled id %u\n", hash->alg_id );
        break;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS hmac_finish( struct hash *hash, UCHAR *output, ULONG size )
{
    CCHmacFinal( &hash->u.hmac_ctx, output );

    return STATUS_SUCCESS;
}
#elif defined(SONAME_LIBGCRYPT)
struct hash
{
    struct object hdr;
    BOOL hmac;
    enum alg_id   alg_id;
    gcry_md_hd_t  hash_handle;
};

struct key
{
    struct object    hdr;
    enum alg_id      alg_id;

    gcry_cipher_hd_t cypher_handle;
};

static NTSTATUS hash_init( struct hash *hash )
{
    TRACE("%p\n", hash);
    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        pgcry_md_open(&hash->hash_handle, GCRY_MD_MD5, 0);
        break;

    case ALG_ID_SHA1:
        pgcry_md_open(&hash->hash_handle, GCRY_MD_SHA1, 0);
        break;

    case ALG_ID_SHA256:
        pgcry_md_open(&hash->hash_handle, GCRY_MD_SHA256, 0);
        break;

    case ALG_ID_SHA384:
        pgcry_md_open(&hash->hash_handle, GCRY_MD_SHA384, 0);
        break;

    case ALG_ID_SHA512:
        pgcry_md_open(&hash->hash_handle, GCRY_MD_SHA512, 0);
        break;

    default:
        ERR( "unhandled id %u\n", hash->alg_id );
        break;
    }

//    pgcry_md_debug (hash->hash_handle, "dump");

    return STATUS_SUCCESS;
}

static NTSTATUS hmac_init( struct hash *hash, UCHAR *key, ULONG key_size )
{
    TRACE("%d\n", key_size);
    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        pgcry_md_open(&hash->hash_handle, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC);
        break;

    case ALG_ID_SHA1:
        pgcry_md_open(&hash->hash_handle, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
        break;

    case ALG_ID_SHA256:
        pgcry_md_open(&hash->hash_handle, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
        break;

    case ALG_ID_SHA384:
        pgcry_md_open(&hash->hash_handle, GCRY_MD_SHA384, GCRY_MD_FLAG_HMAC);
        break;

    case ALG_ID_SHA512:
        pgcry_md_open(&hash->hash_handle, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
        break;

    default:
        ERR( "unhandled id %u\n", hash->alg_id );
        break;
    }
//    pgcry_md_debug (hash->hash_handle, "dumphmac");
    pgcry_md_setkey(hash->hash_handle, key, key_size);
    return STATUS_SUCCESS;
}


static NTSTATUS hash_update( struct hash *hash, UCHAR *input, ULONG size )
{
    pgcry_md_write(hash->hash_handle, input, size);
    return STATUS_SUCCESS;
}

static NTSTATUS hmac_update( struct hash *hash, UCHAR *input, ULONG size )
{
    pgcry_md_write(hash->hash_handle, input, size);
    return STATUS_SUCCESS;
}

static NTSTATUS hash_finish( struct hash *hash, UCHAR *output, ULONG size )
{
    UCHAR* buf;
    pgcry_md_ctl(hash->hash_handle, GCRYCTL_FINALIZE, NULL, 0);
    buf = pgcry_md_read(hash->hash_handle, 0);
    memcpy(output, buf, size);
    pgcry_md_close(hash->hash_handle);
    hash->hash_handle = NULL;

    return STATUS_SUCCESS;
}

static NTSTATUS hmac_finish( struct hash *hash, UCHAR *output, ULONG size )
{
    UCHAR* buf;
    pgcry_md_ctl(hash->hash_handle, GCRYCTL_FINALIZE, NULL, 0);
    buf= pgcry_md_read(hash->hash_handle, 0);
    memcpy(output, buf, size);
    pgcry_md_close(hash->hash_handle);
    hash->hash_handle = NULL;

    return STATUS_SUCCESS;
}

static NTSTATUS hash_duplicate( struct hash *hash,  struct hash **hashout )
{
    struct hash *hashout2;

    if (!(hashout2 = HeapAlloc( GetProcessHeap(), 0, sizeof(*hashout2) )))
    {
     FIXME("no mem\n");
     return STATUS_NO_MEMORY;
    }

    hashout2->hdr.magic = hash->hdr.magic;
    hashout2->alg_id    = hash->alg_id;
    hashout2->hmac      = hash->hmac;

    pgcry_md_copy(&hashout2->hash_handle, hash->hash_handle);
    *hashout = hashout2;

    return STATUS_SUCCESS;
}

static NTSTATUS key_init( struct key *key, UCHAR *secret, ULONG size )
{
    int alg = 0;

    switch (key->alg_id)
    {
    case ALG_ID_AES:
        switch (size)
        {
        case 128 / 8:
            FIXME( "128 bit key provided\n" );
            alg = GCRY_CIPHER_AES;
            break;
        case 192 / 8:
            FIXME( "192 bit key provided\n" );
            alg = GCRY_CIPHER_AES192;
            break;
        case 256 / 8:
            FIXME( "256 bit key provided\n" );
            alg = GCRY_CIPHER_AES256;
            break;
        default:
            ERR( "unhandled key size %u\n", size );
            return STATUS_NOT_IMPLEMENTED;
        }

        break;

    default:
        ERR( "unhandled id %u\n", key->alg_id );
        return STATUS_NOT_IMPLEMENTED;
    }

    if (pgcry_cipher_open( &key->cypher_handle, alg, GCRY_CIPHER_MODE_CBC, 0)) {
        ERR("gcrypt failed to init cipher");
        return STATUS_INTERNAL_ERROR;
    }

    pgcry_cipher_setkey(key->cypher_handle, secret, size);
    return STATUS_SUCCESS;
}

static NTSTATUS key_finish( struct key *key )
{
    pgcry_cipher_close ( key->cypher_handle );
    return STATUS_SUCCESS;
}

static NTSTATUS key_encrypt( struct key *key, UCHAR *input, ULONG input_size, UCHAR *iv, ULONG iv_size, UCHAR *output, ULONG output_size, ULONG flags )
{
    gcry_error_t err;
    UCHAR* padded_input;
    ULONG block_size = 16;
    ULONG blocks = input_size / block_size + 1;

    ULONG delta = block_size*blocks - input_size;

    if (iv) {
        pgcry_cipher_setiv(key->cypher_handle, iv, iv_size);
    }

    if (flags)// && input_size % 16)
    {
        //pad input to block size

        padded_input = HeapAlloc( GetProcessHeap(), 0, block_size*blocks);

        //Windows BCryptEncode seems to write standart PKCS #7 padding
        memset(padded_input,delta,block_size*blocks);
        memcpy(padded_input,input,input_size);

        if (( err = pgcry_cipher_encrypt(key->cypher_handle, output, output_size, padded_input, block_size*blocks))>0)
        {
            FIXME("Failed %d  %s/%s\n", err, pgcry_strsource (err),
                   pgcry_strerror (err));
          return STATUS_INTERNAL_ERROR;
        }
        HeapFree( GetProcessHeap(), 0, padded_input );
    }
    else
    {

        if (( err = pgcry_cipher_encrypt(key->cypher_handle, output, output_size, input, input_size))>0)
        {
            FIXME("Failed %d  %s/%s\n", err, pgcry_strsource (err),
                   pgcry_strerror (err));
          return STATUS_INTERNAL_ERROR;
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS key_decrypt( struct key *key, UCHAR *input, ULONG input_size, UCHAR *iv, ULONG iv_size, UCHAR *output, ULONG output_size, ULONG flags, ULONG* result )
{
    gcry_error_t err;
    UCHAR* padded_input;
    UCHAR* padded_output;
    ULONG block_size = 16;
    ULONG blocks = input_size / block_size;// + 1;
    if (iv) {
        pgcry_cipher_setiv(key->cypher_handle, iv, iv_size);
    }

    if (flags)// && input_size % 16)
    {

        //pad input to block size
        padded_input = HeapAlloc( GetProcessHeap(), 0, block_size*blocks);
        memset(padded_input,0,block_size*blocks);
        memcpy(padded_input,input,input_size);

        // create big enought output
        padded_output = HeapAlloc( GetProcessHeap(), 0, block_size*blocks);
        memset(padded_output,0,block_size*blocks);

        if (( err = pgcry_cipher_decrypt(key->cypher_handle, padded_output, block_size*blocks, padded_input, block_size*blocks))>0)
        {
            FIXME("Failed %d  %s/%s\n", err, pgcry_strsource (err),
                   pgcry_strerror (err));
          return STATUS_INTERNAL_ERROR;
        }

        //truncate
        output_size = block_size*blocks;


        if (padded_output[output_size-1]!=0)
        {
            output_size-=padded_output[output_size-1];
        }

        *result = output_size;

        memcpy(output, padded_output, output_size);

        HeapFree( GetProcessHeap(), 0, padded_input );
        HeapFree( GetProcessHeap(), 0, padded_output );
    }
    else
    {
        if ((err = pgcry_cipher_decrypt(key->cypher_handle, output, output_size, input, input_size))>0)
        {
            FIXME("Failed %d  %s/%s\n", err, pgcry_strsource (err),
                       pgcry_strerror (err));
            return STATUS_INTERNAL_ERROR;
        }
    }
    return STATUS_SUCCESS;
}


#elif defined(HAVE_GNUTLS_HASH)
struct hash
{
    struct object    hdr;
    enum alg_id      alg_id;
    BOOL hmac;
    union
    {
        gnutls_hash_hd_t hash_handle;
        gnutls_hmac_hd_t hmac_handle;
    } u;
};

static NTSTATUS hash_init( struct hash *hash )
{
    gnutls_digest_algorithm_t alg;

    if (!libgnutls_handle) return STATUS_INTERNAL_ERROR;

    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        alg = GNUTLS_DIG_MD5;
        break;
    case ALG_ID_SHA1:
        alg = GNUTLS_DIG_SHA1;
        break;

    case ALG_ID_SHA256:
        alg = GNUTLS_DIG_SHA256;
        break;

    case ALG_ID_SHA384:
        alg = GNUTLS_DIG_SHA384;
        break;

    case ALG_ID_SHA512:
        alg = GNUTLS_DIG_SHA512;
        break;

    default:
        ERR( "unhandled id %u\n", hash->alg_id );
        return STATUS_NOT_IMPLEMENTED;
    }

    if (pgnutls_hash_init( &hash->u.hash_handle, alg )) return STATUS_INTERNAL_ERROR;
    return STATUS_SUCCESS;
}

static NTSTATUS hmac_init( struct hash *hash, UCHAR *key, ULONG key_size )
{
    gnutls_mac_algorithm_t alg;

    if (!libgnutls_handle) return STATUS_INTERNAL_ERROR;

    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        alg = GNUTLS_MAC_MD5;
        break;
    case ALG_ID_SHA1:
        alg = GNUTLS_MAC_SHA1;
        break;

    case ALG_ID_SHA256:
        alg = GNUTLS_MAC_SHA256;
        break;

    case ALG_ID_SHA384:
        alg = GNUTLS_MAC_SHA384;
        break;

    case ALG_ID_SHA512:
        alg = GNUTLS_MAC_SHA512;
        break;

    default:
        ERR( "unhandled id %u\n", hash->alg_id );
        return STATUS_NOT_IMPLEMENTED;
    }

    if (pgnutls_hmac_init( &hash->u.hmac_handle, alg, key, key_size )) return STATUS_INTERNAL_ERROR;
    return STATUS_SUCCESS;
}

static NTSTATUS hash_update( struct hash *hash, UCHAR *input, ULONG size )
{
    if (pgnutls_hash( hash->u.hash_handle, input, size )) return STATUS_INTERNAL_ERROR;
    return STATUS_SUCCESS;
}

static NTSTATUS hmac_update( struct hash *hash, UCHAR *input, ULONG size )
{
    if (pgnutls_hmac( hash->u.hmac_handle, input, size )) return STATUS_INTERNAL_ERROR;
    return STATUS_SUCCESS;
}

static NTSTATUS hash_finish( struct hash *hash, UCHAR *output, ULONG size )
{
    pgnutls_hash_deinit( hash->u.hash_handle, output );
    return STATUS_SUCCESS;
}

static NTSTATUS hmac_finish( struct hash *hash, UCHAR *output, ULONG size )
{
    pgnutls_hmac_deinit( hash->u.hmac_handle, output );
    return STATUS_SUCCESS;
}
#else
struct hash
{
    struct object hdr;
    BOOL hmac;
    enum alg_id   alg_id;
};

static NTSTATUS hash_init( struct hash *hash )
{
    ERR( "support for hashes not available at build time\n" );
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS hmac_init( struct hash *hash, UCHAR *key, ULONG key_size )
{
    ERR( "support for hashes not available at build time\n" );
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS hash_update( struct hash *hash, UCHAR *input, ULONG size )
{
    ERR( "support for hashes not available at build time\n" );
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS hmac_update( struct hash *hash, UCHAR *input, ULONG size )
{
    ERR( "support for hashes not available at build time\n" );
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS hash_finish( struct hash *hash, UCHAR *output, ULONG size )
{
    ERR( "support for hashes not available at build time\n" );
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS hmac_finish( struct hash *hash, UCHAR *output, ULONG size )
{
    ERR( "support for hashes not available at build time\n" );
    return STATUS_NOT_IMPLEMENTED;
}
#endif

#define OBJECT_LENGTH_MD5       274
#define OBJECT_LENGTH_SHA1      278
#define OBJECT_LENGTH_SHA256    286
#define OBJECT_LENGTH_SHA384    382
#define OBJECT_LENGTH_SHA512    382

#define OBJECT_LENGTH_AES       4

// 128 bit key size default
#define BLOCK_LENGTH_AES        16

static NTSTATUS generic_alg_property( enum alg_id id, const WCHAR *prop, UCHAR *buf, ULONG size, ULONG *ret_size )
{
    if (!strcmpW( prop, BCRYPT_HASH_LENGTH ))
    {
        *ret_size = sizeof(ULONG);
        if (size < sizeof(ULONG))
            return STATUS_BUFFER_TOO_SMALL;
        if(buf)
            *(ULONG*)buf = alg_props[id].hash_length;
        return STATUS_SUCCESS;
    }

    if (!strcmpW( prop, BCRYPT_ALGORITHM_NAME ))
    {
        *ret_size = (strlenW(alg_props[id].alg_name)+1)*sizeof(WCHAR);
        if (size < *ret_size)
            return STATUS_BUFFER_TOO_SMALL;
        if(buf)
            memcpy(buf, alg_props[id].alg_name, *ret_size);
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS get_alg_property( enum alg_id id, const WCHAR *prop, UCHAR *buf, ULONG size, ULONG *ret_size )
{
    NTSTATUS status;
    ULONG value;

    status = generic_alg_property( id, prop, buf, size, ret_size );
    if (status != STATUS_NOT_IMPLEMENTED)
        return status;

    switch (id)
    {
    case ALG_ID_MD5:
        if (!strcmpW( prop, BCRYPT_OBJECT_LENGTH ))
        {
            value = OBJECT_LENGTH_MD5;
            break;
        }
        FIXME( "unsupported md5 algorithm property %s\n", debugstr_w(prop) );
        return STATUS_NOT_IMPLEMENTED;

    case ALG_ID_RNG:
        if (!strcmpW( prop, BCRYPT_OBJECT_LENGTH )) return STATUS_NOT_SUPPORTED;
        FIXME( "unsupported rng algorithm property %s\n", debugstr_w(prop) );
        return STATUS_NOT_IMPLEMENTED;

    case ALG_ID_SHA1:
        if (!strcmpW( prop, BCRYPT_OBJECT_LENGTH ))
        {
            value = OBJECT_LENGTH_SHA1;
            break;
        }
        FIXME( "unsupported sha1 algorithm property %s\n", debugstr_w(prop) );
        return STATUS_NOT_IMPLEMENTED;

    case ALG_ID_SHA256:
        if (!strcmpW( prop, BCRYPT_OBJECT_LENGTH ))
        {
            value = OBJECT_LENGTH_SHA256;
            break;
        }
        FIXME( "unsupported sha256 algorithm property %s\n", debugstr_w(prop) );
        return STATUS_NOT_IMPLEMENTED;

    case ALG_ID_SHA384:
        if (!strcmpW( prop, BCRYPT_OBJECT_LENGTH ))
        {
            value = OBJECT_LENGTH_SHA384;
            break;
        }
        FIXME( "unsupported sha384 algorithm property %s\n", debugstr_w(prop) );
        return STATUS_NOT_IMPLEMENTED;

    case ALG_ID_SHA512:
        if (!strcmpW( prop, BCRYPT_OBJECT_LENGTH ))
        {
            value = OBJECT_LENGTH_SHA512;
            break;
        }
        FIXME( "unsupported sha512 algorithm property %s\n", debugstr_w(prop) );
        return STATUS_NOT_IMPLEMENTED;

    case ALG_ID_AES:
        if (!strcmpW( prop, BCRYPT_BLOCK_LENGTH ))
        {
            value = BLOCK_LENGTH_AES;
            break;
        }
        if (!strcmpW( prop, BCRYPT_OBJECT_LENGTH ))
        {
            value = OBJECT_LENGTH_AES;
            break;
        }
        FIXME( "unsupported aes algorithm property %s\n", debugstr_w(prop) );
        return STATUS_NOT_IMPLEMENTED;

    default:
        FIXME( "unsupported algorithm %u\n", id );
        return STATUS_NOT_IMPLEMENTED;
    }

    if (size < sizeof(ULONG))
    {
        *ret_size = sizeof(ULONG);
        FIXME( "buffer too small\n");
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (buf) *(ULONG *)buf = value;
    *ret_size = sizeof(ULONG);

    return STATUS_SUCCESS;
}

static NTSTATUS get_hash_property( enum alg_id id, const WCHAR *prop, UCHAR *buf, ULONG size, ULONG *ret_size )
{
    NTSTATUS status;

    status = generic_alg_property( id, prop, buf, size, ret_size );
    if (status == STATUS_NOT_IMPLEMENTED)
        FIXME( "unsupported property %s\n", debugstr_w(prop) );
    return status;
}

NTSTATUS WINAPI BCryptGetProperty( BCRYPT_HANDLE handle, LPCWSTR prop, UCHAR *buffer, ULONG count, ULONG *res, ULONG flags )
{
    struct object *object = handle;

    TRACE( "%p, %s, %p, %u, %p, %08x\n", handle, wine_dbgstr_w(prop), buffer, count, res, flags );

    if (!object) return STATUS_INVALID_HANDLE;
    if (!prop || !res) return STATUS_INVALID_PARAMETER;

    switch (object->magic)
    {
    case MAGIC_ALG:
    {
        const struct algorithm *alg = (const struct algorithm *)object;
        return get_alg_property( alg->id, prop, buffer, count, res );
    }
    case MAGIC_HASH:
    {
        const struct hash *hash = (const struct hash *)object;
        return get_hash_property( hash->alg_id, prop, buffer, count, res );
    }
    default:
        WARN( "unknown magic %08x\n", object->magic );
        return STATUS_INVALID_HANDLE;
    }
}

NTSTATUS WINAPI BCryptCreateHash( BCRYPT_ALG_HANDLE algorithm, BCRYPT_HASH_HANDLE *handle, UCHAR *object, ULONG objectlen,
                                  UCHAR *secret, ULONG secretlen, ULONG flags )
{
    struct algorithm *alg = algorithm;
    struct hash *hash;
    NTSTATUS status;

    TRACE( "%p, %p, %p, %u, %p, %u, %08x - stub\n", algorithm, handle, object, objectlen,
           secret, secretlen, flags );

    if (flags)
    {
        FIXME( "unimplemented flags %08x\n", flags );
        return STATUS_NOT_IMPLEMENTED;
    }

    if (!alg || alg->hdr.magic != MAGIC_ALG)
    {
     FIXME( "invalid handle!!\n" );
     return STATUS_INVALID_HANDLE;
    }
    if (object) FIXME( "ignoring object buffer!!\n" );

    if (!(hash = HeapAlloc( GetProcessHeap(), 0, sizeof(*hash) )))
    {
    FIXME( "no memory!!\n" );
    return STATUS_NO_MEMORY;
    }

    hash->hdr.magic = MAGIC_HASH;
    hash->alg_id    = alg->id;
    hash->hmac      = alg->hmac;

    if (hash->hmac)
    {
        status = hmac_init( hash, secret, secretlen );
    }
    else
    {
        status = hash_init( hash );
    }

    if (status != STATUS_SUCCESS)
    {
        HeapFree( GetProcessHeap(), 0, hash );
        FIXME( "WUT\n" );
        return status;
    }

    *handle = hash;
    TRACE("%p\n", hash);
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptDestroyHash( BCRYPT_HASH_HANDLE handle )
{
    struct hash *hash = handle;

    TRACE( "%p\n", handle );

    if (!hash || hash->hdr.magic != MAGIC_HASH) return STATUS_INVALID_HANDLE;
    HeapFree( GetProcessHeap(), 0, hash );
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptHashData( BCRYPT_HASH_HANDLE handle, UCHAR *input, ULONG size, ULONG flags )
{
    struct hash *hash = handle;

    TRACE( "%p, %p, %u, %08x\n", handle, input, size, flags );

    if (!hash || hash->hdr.magic != MAGIC_HASH) return STATUS_INVALID_HANDLE;
    if (!input) return STATUS_SUCCESS;

    if (hash->hmac)
    {
        return hmac_update( hash, input, size );
    }
    else
    {
        return hash_update( hash, input, size );
    }
}

NTSTATUS WINAPI BCryptFinishHash( BCRYPT_HASH_HANDLE handle, UCHAR *output, ULONG size, ULONG flags )
{
    struct hash *hash = handle;

    TRACE( "%p, %p, %u, %08x\n", handle, output, size, flags );

    if (!hash || hash->hdr.magic != MAGIC_HASH) return STATUS_INVALID_HANDLE;
    if (!output) return STATUS_INVALID_PARAMETER;

    if (hash->hmac)
    {
        return hmac_finish( hash, output, size );
    }
    else
    {
        return hash_finish( hash, output, size );
    }
}

NTSTATUS WINAPI BCryptHash( BCRYPT_ALG_HANDLE algorithm, UCHAR *secret, ULONG secretlen,
                            UCHAR *input, ULONG inputlen, UCHAR *output, ULONG outputlen )
{
    NTSTATUS status;
    BCRYPT_HASH_HANDLE handle;

    TRACE( "%p, %p, %u, %p, %u, %p, %u\n", algorithm, secret, secretlen,
           input, inputlen, output, outputlen );

    status = BCryptCreateHash( algorithm, &handle, NULL, 0, secret, secretlen, 0);
    if (status != STATUS_SUCCESS)
    {
        return status;
    }

    status = BCryptHashData( handle, input, inputlen, 0 );
    if (status != STATUS_SUCCESS)
    {
        BCryptDestroyHash( handle );
        return status;
    }

    status = BCryptFinishHash( handle, output, outputlen, 0 );
    if (status != STATUS_SUCCESS)
    {
        BCryptDestroyHash( handle );
        return status;
    }

    return BCryptDestroyHash( handle );
}

NTSTATUS WINAPI BCryptDuplicateHash( BCRYPT_HASH_HANDLE handle, BCRYPT_HASH_HANDLE *hash_handle_out, UCHAR *object, ULONG object_size, ULONG flags)
{
    struct hash *hash = handle;
    struct hash *duplicate;
    NTSTATUS status;

    TRACE( "%p %p %p %u %08x\n",
        handle,
        hash_handle_out,
        object,
        object_size,
        flags
    );

    if (flags) {
        FIXME( "unimplemented flags %08x\n", flags );
    }

    if (object) FIXME( "ignoring object buffer\n" );

    if (!hash || hash->hdr.magic != MAGIC_HASH) return STATUS_INVALID_HANDLE;

    status = hash_duplicate(hash, &duplicate);

    if (status != STATUS_SUCCESS) {
        return status;
    }

    *hash_handle_out = duplicate;

    TRACE( "hash duplicate OK %p %p\n",  hash_handle_out, duplicate);
    return STATUS_SUCCESS;
}


NTSTATUS WINAPI BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE algorithm, BCRYPT_KEY_HANDLE *key_handle_out, UCHAR *key_object, ULONG key_object_size, UCHAR *secret, ULONG secret_size, ULONG flags)
{
    struct key *key;
    struct algorithm *alg = algorithm;
    NTSTATUS status;

    TRACE("%p %p %p %u %p %u %08x\n",
        algorithm,
        key_handle_out,
        key_object,
        key_object_size,
        secret,
        secret_size,
        flags
    );

    if (key_object) FIXME( "ignoring object buffer\n" );

    // if (!alg || alg->hdr.magic != MAGIC_ALG) return STATUS_INVALID_HANDLE;
    if (!alg || alg->hdr.magic != MAGIC_ALG) {
        FIXME("invalid alg handle");
        return STATUS_INVALID_HANDLE;
    }

    if (!(key = HeapAlloc( GetProcessHeap(), 0, sizeof(*key) ))) return STATUS_NO_MEMORY;

    key->hdr.magic = MAGIC_KEY;
    key->alg_id = alg->id;

    status = key_init(key, secret, secret_size);

    if (status != STATUS_SUCCESS) {
        ERR("key initiazation failed");
        HeapFree( GetProcessHeap(), 0, key );
        return status;
    }

    *key_handle_out = key;
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptDestroyKey(BCRYPT_KEY_HANDLE handle)
{
    struct key *key = handle;

    TRACE( "%p\n", handle );

    // if (!key || key->hdr.magic != MAGIC_KEY) return STATUS_INVALID_HANDLE;
    if (!key || key->hdr.magic != MAGIC_KEY) {
        ERR("invalid key handle");
        return STATUS_INVALID_HANDLE;
    }

    key_finish(key);

    HeapFree( GetProcessHeap(), 0, key );
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptEncrypt(BCRYPT_KEY_HANDLE handle, UCHAR *pbInput, ULONG cbInput, void *pPaddingInfo, UCHAR *pbIV, ULONG cbIV, UCHAR *pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG flags)
{
    struct key *key = handle;

    TRACE( "%p %p %u %p %p %u %p %u %p %08x\n",
        handle,
        pbInput,
        cbInput,
        pPaddingInfo,
        pbIV,
        cbIV,
        pbOutput,
        cbOutput,
        pcbResult,
        flags
    );

    // if (!key || key->hdr.magic != MAGIC_KEY) return STATUS_INVALID_HANDLE;
    if (!key || key->hdr.magic != MAGIC_KEY) {
        ERR("invalid key handle");
        return STATUS_INVALID_HANDLE;
    }

    *pcbResult = cbOutput;

    return key_encrypt(key, pbInput, cbInput, pbIV, cbIV, pbOutput, cbOutput, flags );
}

NTSTATUS WINAPI BCryptDecrypt(BCRYPT_KEY_HANDLE handle, UCHAR *pbInput, ULONG cbInput, void *pPaddingInfo, UCHAR *pbIV, ULONG cbIV, UCHAR *pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG flags)
{
    struct key *key = handle;

    TRACE( "%p %p %u %p %p %u %p %u %p %08x\n",
        handle,
        pbInput,
        cbInput,
        pPaddingInfo,
        pbIV,
        cbIV,
        pbOutput,
        cbOutput,
        pcbResult,
        flags
    );

    // if (!key || key->hdr.magic != MAGIC_KEY) return STATUS_INVALID_HANDLE;
    if (!key || key->hdr.magic != MAGIC_KEY) {
        ERR("invalid key handle");
        return STATUS_INVALID_HANDLE;
    }

    *pcbResult = cbOutput;

    return key_decrypt(key, pbInput, cbInput, pbIV, cbIV, pbOutput, cbOutput, flags, pcbResult );
}

BOOL WINAPI DllMain( HINSTANCE hinst, DWORD reason, LPVOID reserved )
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        instance = hinst;
        DisableThreadLibraryCalls( hinst );
#if defined(SONAME_LIBGCRYPT) && !defined(HAVE_COMMONCRYPTO_COMMONDIGEST_H)
        gcrypt_initialize();
#elif defined(HAVE_GNUTLS_HASH) && !defined(HAVE_COMMONCRYPTO_COMMONDIGEST_H)
        gnutls_initialize();
#endif
        break;

    case DLL_PROCESS_DETACH:
        if (reserved) break;
#if defined(SONAME_LIBGCRYPT) && !defined(HAVE_COMMONCRYPTO_COMMONDIGEST_H)
        gcrypt_uninitialize();
#elif defined(HAVE_GNUTLS_HASH) && !defined(HAVE_COMMONCRYPTO_COMMONDIGEST_H)
        gnutls_uninitialize();
#endif
        break;
    }
    return TRUE;
}
