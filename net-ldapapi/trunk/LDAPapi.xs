/* This file was modified by Howard Chu, hyc@symas.com, 2000-2003.
 * Most changes are #if OPENLDAP, some are not marked.
 */
#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
}
#endif

#include <lber.h>
#include <ldap.h>

/* Mozilla prototypes declare things as "const char *" while   */
/*      OpenLDAP uses "char *"                                 */

#ifdef MOZILLA_LDAP
 #define LDAP_CHAR const char
 #include <ldap_ssl.h>
#else
#ifndef OPENLDAP
 #include "ldap_compat.h"
#endif
 #define LDAP_CHAR char
#endif


/* Function Prototypes for Internal Functions */

static char **av2modvals(AV *ldap_value_array_av, int ldap_isa_ber);
static LDAPMod *parse1mod(SV *ldap_value_ref,char *ldap_current_attribute,
	int ldap_add_func,int cont);
static LDAPMod **hash2mod(SV *ldap_change,int ldap_add_func, const char *func);

#ifdef MOZILLA_LDAP
   static int internal_rebind_proc(LDAP *ld, char **dnp, char **pwp,
	   int *authmethodp, int freeit, void *arg);
   static int LDAP_CALL ns_internal_rebind_proc(LDAP *ld, char **dnp,
            char **pwp, int *authmethodp, int freeit, void *arg)
   {
      return internal_rebind_proc(ld,dnp,pwp,authmethodp,freeit,arg);
   }
#else
   static int internal_rebind_proc(LDAP *ld, char **dnp, char **pwp,
	   int *authmethodp, int freeit);
#endif

/* The Name of the PERL function to return DN, PASSWD, AUTHTYPE on Rebind */
/* Set using 'set_rebind_proc()' */
SV *ldap_perl_rebindproc = NULL;


/* Use constant.h generated from constant.gen */
/* Courtesy of h.b.furuseth@usit.uio.no       */

#include "constant.h"

/* Strcasecmp - Some operating systems don't have this, including NT */

int StrCaseCmp(const char *s, const char *t)
{
   while (*s && *t && toupper(*s) == toupper(*t))
   {
      s++; t++;
   }
   return(toupper(*s) - toupper(*t));
}

/* av2modvals - Takes a single Array Reference (AV *) and returns */
/*    a null terminated list of char pointers.                    */

static
char **av2modvals(AV *ldap_value_array_av, int ldap_isa_ber)
{
   I32 ldap_arraylen;
   char **ldap_ch_modvalues = NULL;
   char *ldap_current_value_char = NULL;
   struct berval **ldap_bv_modvalues = NULL;
   struct berval *ldap_current_bval = NULL;
   SV **ldap_current_value_sv;
   int ldap_value_count = 0,ldap_pvlen,ldap_real_valuecount = 0;

   ldap_arraylen = av_len(ldap_value_array_av);
   if (ldap_arraylen < 0)
      return(NULL);

   if (ldap_isa_ber == 1)
   {
      New(1,ldap_bv_modvalues,2+ldap_arraylen,struct berval *);
   } else {
      New(1,ldap_ch_modvalues,2+ldap_arraylen,char *);
   }

   for (ldap_value_count = 0; ldap_value_count <=ldap_arraylen;
	ldap_value_count++)
   {
      ldap_current_value_sv = av_fetch(ldap_value_array_av,ldap_value_count,0);
      ldap_current_value_char = SvPV(*ldap_current_value_sv,PL_na);
      ldap_pvlen = SvCUR(*ldap_current_value_sv);
      if (strcmp(ldap_current_value_char,"") != 0)
      {
         if (ldap_isa_ber == 1)
         {
            New(1,ldap_current_bval,1,struct berval);
	    ldap_current_bval->bv_len = ldap_pvlen;
	    ldap_current_bval->bv_val = ldap_current_value_char;
	    ldap_bv_modvalues[ldap_real_valuecount] = ldap_current_bval;
         } else {
            ldap_ch_modvalues[ldap_real_valuecount] = ldap_current_value_char;
         }
         ldap_real_valuecount++;
      }
   }
   if (ldap_isa_ber == 1)
   {
      ldap_bv_modvalues[ldap_real_valuecount] = NULL;
      return ((char **)ldap_bv_modvalues);
   } else {
      ldap_ch_modvalues[ldap_real_valuecount] = NULL;
      return (ldap_ch_modvalues);
   }
}


/* parse1mod - Take a single reference, figure out if it is a HASH, */
/*   ARRAY, or SCALAR, then extract the values and attributes and   */
/*   return a single LDAPMod pointer to this data.                  */

static
LDAPMod *parse1mod(SV *ldap_value_ref,char *ldap_current_attribute,
   int ldap_add_func,int cont)
{
   LDAPMod *ldap_current_mod;
   static HV *ldap_current_values_hv;
   HE *ldap_change_element;
   char *ldap_current_modop;
   SV *ldap_current_value_sv;
   I32 keylen;
   int ldap_isa_ber = 0;

   if (ldap_current_attribute == NULL)
      return(NULL);
   New(1,ldap_current_mod,1,LDAPMod);
   ldap_current_mod->mod_type = ldap_current_attribute;
   if (SvROK(ldap_value_ref))
   {
     if (SvTYPE(SvRV(ldap_value_ref)) == SVt_PVHV)
     {
      if (!cont)
      {
         ldap_current_values_hv = (HV *) SvRV(ldap_value_ref);
         hv_iterinit(ldap_current_values_hv);
      }
      if ((ldap_change_element = hv_iternext(ldap_current_values_hv)) == NULL)
	 return(NULL);
      ldap_current_modop = hv_iterkey(ldap_change_element,&keylen);
      ldap_current_value_sv = hv_iterval(ldap_current_values_hv,
	ldap_change_element);
      if (ldap_add_func == 1)
      {
	 ldap_current_mod->mod_op = 0;
      } else {
	 if (strchr(ldap_current_modop,'a') != NULL)
	 {
	    ldap_current_mod->mod_op = LDAP_MOD_ADD;
	 } else if (strchr(ldap_current_modop,'r') != NULL)
	 {
	    ldap_current_mod->mod_op = LDAP_MOD_REPLACE;
	 } else if (strchr(ldap_current_modop,'d') != NULL) {
	    ldap_current_mod->mod_op = LDAP_MOD_DELETE;
	 } else {
	    return(NULL);
	 }
      }
      if (strchr(ldap_current_modop,'b') != NULL)
      {
	 ldap_isa_ber = 1;
	 ldap_current_mod->mod_op = ldap_current_mod->mod_op | LDAP_MOD_BVALUES;
      }
      if (SvTYPE(SvRV(ldap_current_value_sv)) == SVt_PVAV)
      {
	 if (ldap_isa_ber == 1)
	 {
	    ldap_current_mod->mod_values =
	      av2modvals((AV *)SvRV(ldap_current_value_sv),ldap_isa_ber);
	 } else {
	    ldap_current_mod->mod_values =
	      av2modvals((AV *)SvRV(ldap_current_value_sv),ldap_isa_ber);
	 }
      }
     } else if (SvTYPE(SvRV(ldap_value_ref)) == SVt_PVAV) {
      if (cont)
         return NULL;
      if (ldap_add_func == 1)
         ldap_current_mod->mod_op = 0;
      else
         ldap_current_mod->mod_op = LDAP_MOD_REPLACE;
      ldap_current_mod->mod_values = av2modvals((AV *)SvRV(ldap_value_ref),0);
      if (ldap_current_mod->mod_values == NULL)
      {
	 ldap_current_mod->mod_op = LDAP_MOD_DELETE;
      }
     }
   } else {
      if (cont)
         return NULL;
      if (strcmp(SvPV(ldap_value_ref,PL_na),"") == 0)
      {
         if (ldap_add_func != 1)
         {
	    ldap_current_mod->mod_op = LDAP_MOD_DELETE;
	    ldap_current_mod->mod_values = NULL;
         } else {
            return(NULL);
         }
      } else {
         if (ldap_add_func == 1)
         {
            ldap_current_mod->mod_op = 0;
         } else {
	    ldap_current_mod->mod_op = LDAP_MOD_REPLACE;
         }
         New(1,ldap_current_mod->mod_values,2,char *);
	 ldap_current_mod->mod_values[0] = SvPV(ldap_value_ref,PL_na);
	 ldap_current_mod->mod_values[1] = NULL;
      }
   }
   return(ldap_current_mod);
}


/* hash2mod - Cycle through all the keys in the hash and properly call */
/*    the appropriate functions to build a NULL terminated list of     */
/*    LDAPMod pointers.                                                */

static
LDAPMod ** hash2mod(SV *ldap_change_ref,int ldap_add_func,const char *func)
{
   LDAPMod **ldapmod = NULL;
   LDAPMod *ldap_current_mod;
   int ldap_attribute_count = 0;
   HE *ldap_change_element;
   char *ldap_current_attribute;
   SV *ldap_current_value_sv;
   I32 keylen;
   HV *ldap_change;

   if (!SvROK(ldap_change_ref) || SvTYPE(SvRV(ldap_change_ref)) != SVt_PVHV)
      croak("Net::LDAPapi::%s needs Hash reference as argument 3.",func);

   ldap_change = (HV *)SvRV(ldap_change_ref);

   hv_iterinit(ldap_change);
   while((ldap_change_element = hv_iternext(ldap_change)) != NULL)
   {
      ldap_current_attribute = hv_iterkey(ldap_change_element,&keylen);
      ldap_current_value_sv = hv_iterval(ldap_change,ldap_change_element);
      ldap_current_mod = parse1mod(ldap_current_value_sv,
	ldap_current_attribute,ldap_add_func,0);
      while (ldap_current_mod != NULL)
      {
         ldap_attribute_count++;
         (ldapmod
	   ? Renew(ldapmod,1+ldap_attribute_count,LDAPMod *)
	   : New(1,ldapmod,1+ldap_attribute_count,LDAPMod *));
         New(1,ldapmod[ldap_attribute_count -1],sizeof(LDAPMod),LDAPMod);
         Copy(ldap_current_mod,ldapmod[ldap_attribute_count-1],
	   sizeof(LDAPMod),LDAPMod *);
         ldap_current_mod = parse1mod(ldap_current_value_sv,
           ldap_current_attribute,ldap_add_func,1);

      }
   }
   ldapmod[ldap_attribute_count] = NULL;
   return ldapmod;
}

/* internal_rebind_proc - Wrapper to call a PERL rebind process               */
/*   ldap_set_rebind_proc is slightly different between Mozilla and OpenLDAP  */

int
#ifdef MOZILLA_LDAP
internal_rebind_proc(LDAP *ld, char **dnp, char **pwp, int *authmethodp,
  int freeit, void *arg)
#else
internal_rebind_proc(LDAP *ld, char **dnp, char **pwp, int *authmethodp,
  int freeit)
#endif
{

   if (freeit == 0)
   {
      int count = 0;
      dSP;

      ENTER ;
      SAVETMPS ;
      count = perl_call_sv(ldap_perl_rebindproc,G_ARRAY|G_NOARGS);

      SPAGAIN;

      if (count != 3)
 	 croak("ldap_perl_rebindproc: Expected DN, PASSWORD, and AUTHTYPE returned.\n");

      *authmethodp = POPi;
      *pwp = strdup(POPp);
      *dnp = strdup(POPp);

      FREETMPS ;
      LEAVE ;
   } else {
      if (dnp && *dnp)
      {
         free(*dnp);
      }
      if (pwp && *pwp)
      {
         free(*pwp);
      }
   }
   return(LDAP_SUCCESS);
}

#ifdef OPENLDAP

#include "sasl/sasl.h"

typedef struct bictx {
	char *authcid;
	char *passwd;
	char *realm;
	char *authzid;
} bictx;

static int
ldap_b2_interact(LDAP *ld, unsigned flags, void *def, void *inter)
{
	sasl_interact_t *in = inter;
	const char *p;
	bictx *ctx = def;

	for (;in->id != SASL_CB_LIST_END;in++)
	{
		p = NULL;
		switch(in->id)
		{
			case SASL_CB_GETREALM:
				p = ctx->realm;
				break;
			case SASL_CB_AUTHNAME:
				p = ctx->authcid;
				break;
			case SASL_CB_USER:
				p = ctx->authzid;
				break;
			case SASL_CB_PASS:
				p = ctx->passwd;
				break;
		}
		if (p)
		{
			in->len = strlen(p);
			in->result = p;
		}
	}
	return LDAP_SUCCESS;
}

#endif


MODULE = Net::LDAPapi           PACKAGE = Net::LDAPapi

PROTOTYPES: ENABLE

double
constant(name,arg)
	char *          name
	int             arg


LDAP *
ldap_open(host,port)
	LDAP_CHAR *     host
	int             port

LDAP *
ldap_init(defhost,defport)
	LDAP_CHAR *     defhost
	int             defport
	CODE:
	{
	   RETVAL = ldap_init(defhost, defport);
	}
	OUTPUT:
	RETVAL


#ifdef OPENLDAP

int
ldap_initialize(ld,url)
	LDAP *		ld = NO_INIT
	LDAP_CHAR *	url
	CODE:
	{
	   RETVAL = ldap_initialize(&ld, url);
	}
	OUTPUT:
	RETVAL
	ld

#endif


#if defined(MOZILLA_LDAP) || defined(OPENLDAP)

int
ldap_set_option(ld,option,optdata)
	LDAP *          ld
	int             option
	int             optdata
	CODE:
	{
	   RETVAL = ldap_set_option(ld,option,&optdata);
	}
	OUTPUT:
	RETVAL

int
ldap_get_option(ld,option,optdata)
	LDAP *          ld
	int             option
	int             optdata = NO_INIT
	CODE:
	{
	   RETVAL = ldap_get_option(ld,option,&optdata);
	}
	OUTPUT:
	RETVAL
	optdata

#else

int
ldap_set_option(ld,option,optdata)
	LDAP *          ld
	int             option
	int             optdata
	CODE:
	{
	   RETVAL = 0;
	   switch (option)
	   {
	      case LDAP_OPT_DEREF: ld->ld_deref = optdata; break;
	      case LDAP_OPT_SIZELIMIT: ld->ld_sizelimit = optdata; break;
	      case LDAP_OPT_TIMELIMIT: ld->ld_timelimit = optdata; break;
	      case LDAP_OPT_REFERRALS: if (optdata == LDAP_OPT_ON)
		    ld->ld_options |= LDAP_OPT_REFERRALS; else 
		      ld->ld_options &= ~LDAP_OPT_REFERRALS; break;
	      default: RETVAL = -1; break;
	   }
	}
	OUTPUT:
	RETVAL

int
ldap_get_option(ld,option,optdata)
	LDAP *          ld
	int             option
	int             optdata = NO_INIT
	CODE:
	{
	   RETVAL = 0;
	   switch (option)
	   {
	      case LDAP_OPT_DEREF: optdata = ld->ld_deref; break;
	      case LDAP_OPT_SIZELIMIT: optdata = ld->ld_sizelimit; break;
	      case LDAP_OPT_TIMELIMIT: optdata = ld->ld_timelimit; break;
	      case LDAP_OPT_REFERRALS: if (ld->ld_options & LDAP_OPT_REFERRALS)
		    optdata = LDAP_OPT_ON; else optdata = LDAP_OPT_OFF;
		    break;
	      default: RETVAL = optdata = -1; break;
	   }
	}
	OUTPUT:
	RETVAL
	optdata
	

#endif

int
ldap_unbind(ld)
	LDAP *          ld
	
int
ldap_unbind_s(ld)
	LDAP *          ld

#ifdef MOZILLA_LDAP

int
ldap_version(ver)
	LDAPVersion     *ver

#endif

int
ldap_abandon(ld,msgid)
	LDAP *          ld
	int             msgid

int
ldap_add(ld,dn,ldap_change_ref)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAPMod **	ldap_change_ref = hash2mod($arg, 1, "$func_name");
##	CLEANUP:
##	   ldap_mods_free(ldap_change_ref,0);

int
ldap_add_s(ld,dn,ldap_change_ref)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAPMod **	ldap_change_ref = hash2mod($arg, 1, "$func_name");
	CLEANUP:
	   Safefree(ldap_change_ref);
##	   ldap_mods_free(ldap_change_ref,0);

int
ldap_bind(ld,who,passwd,type)
	LDAP *          ld
	LDAP_CHAR *     who
	LDAP_CHAR *     passwd
	int             type

int
ldap_bind_s(ld,who,passwd,type)
	LDAP *          ld
	LDAP_CHAR *     who
	LDAP_CHAR *     passwd
	int             type

int
ldap_simple_bind(ld,who,passwd)
	LDAP *          ld
	LDAP_CHAR *     who
	LDAP_CHAR *     passwd

int
ldap_simple_bind_s(ld,who,passwd)
	LDAP *          ld
	LDAP_CHAR *     who
	LDAP_CHAR *     passwd

int
ldap_modify(ld,dn,ldap_change_ref)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAPMod **	ldap_change_ref = hash2mod($arg, 0, "$func_name");
##	CLEANUP:
##	   ldap_mods_free(ldap_change_ref,0);

int
ldap_modify_s(ld,dn,ldap_change_ref)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAPMod **	ldap_change_ref = hash2mod($arg, 0, "$func_name");

int
ldap_modrdn(ld,dn,newrdn)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAP_CHAR *     newrdn

int
ldap_modrdn_s(ld,dn,newrdn)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAP_CHAR *     newrdn

int
ldap_modrdn2(ld,dn,newrdn,deleteoldrdn)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAP_CHAR *     newrdn
	int             deleteoldrdn

int
ldap_modrdn2_s(ld,dn,newrdn,deleteoldrdn)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAP_CHAR *     newrdn
	int             deleteoldrdn

int
ldap_compare(ld,dn,attr,value)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAP_CHAR *     attr
	LDAP_CHAR *     value

int
ldap_compare_s(ld,dn,attr,value)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAP_CHAR *     attr
	LDAP_CHAR *     value

int
ldap_delete(ld,dn)
	LDAP *          ld
	LDAP_CHAR *     dn

int
ldap_delete_s(ld,dn)
	LDAP *          ld
	LDAP_CHAR *     dn

int
ldap_search(ld,base,scope,filter,attrs,attrsonly)
	LDAP *          ld
	LDAP_CHAR *     base
	int             scope
	LDAP_CHAR *     filter
	SV *            attrs
	int             attrsonly
	CODE:
	{
	   char **attrs_char;
	   SV **current;
	   int arraylen,count;

	   if (SvTYPE(SvRV(attrs)) != SVt_PVAV)
	   {
	      croak("Net::LDAPapi::ldap_search needs ARRAY reference as argument 5.");
	      XSRETURN(1);
	   }
	   if ((arraylen = av_len((AV *)SvRV(attrs))) < 0)
	   {
	      New(1,attrs_char,2,char *);
	      attrs_char[0] = NULL;
	   } else {
	      New(1,attrs_char,arraylen+2,char *);
	      for (count=0;count <= arraylen; count++)
	      {
		 current = av_fetch((AV *)SvRV(attrs),count,0);
		 attrs_char[count] = SvPV(*current,PL_na);
	      }
	      attrs_char[arraylen+1] = NULL;
	   }
	   RETVAL = ldap_search(ld,base,scope,filter,attrs_char,attrsonly);
	   Safefree(attrs_char);
	}
	OUTPUT:
	RETVAL

int
ldap_search_s(ld,base,scope,filter,attrs,attrsonly,res)
	LDAP *          ld
	LDAP_CHAR *     base
	int             scope
	LDAP_CHAR *     filter
	SV *            attrs
	int             attrsonly
	LDAPMessage *   res = NO_INIT
	CODE:
	{
	   char **attrs_char;
	   SV **current;
	   int arraylen,count;

	   if (SvTYPE(SvRV(attrs)) == SVt_PVAV)
	   {
	      if ((arraylen = av_len((AV *)SvRV(attrs))) < 0)
	      {
	         New(1,attrs_char,2,char *);
		 attrs_char[0] = NULL;
	      } else {
	         New(1,attrs_char,arraylen+2,char *);
		 for (count=0;count <= arraylen; count++)
		 {
		    current = av_fetch((AV *)SvRV(attrs),count,0);
		    attrs_char[count] = SvPV(*current,PL_na);
		 }
		 attrs_char[arraylen+1] = NULL;
	      }
	   } else {
	      croak("Net::LDAPapi::ldap_search_s needs ARRAY reference as argument 5.");
	      XSRETURN(1);
	   }
	   RETVAL = ldap_search_s(ld,base,scope,filter,attrs_char,attrsonly,&res);
	   Safefree(attrs_char);
	}
	OUTPUT:
	RETVAL
	res

int
ldap_search_st(ld,base,scope,filter,attrs,attrsonly,timeout,res)
	LDAP *          ld
	LDAP_CHAR *    base
	int             scope
	LDAP_CHAR *    filter
	SV *            attrs
	int             attrsonly
	LDAP_CHAR *     timeout
	LDAPMessage *   res = NO_INIT
	CODE:
	{
	   struct timeval *tv_timeout = NULL, timeoutbuf;
	   char **attrs_char;
	   SV **current;
	   int arraylen,count;

	   if (SvTYPE(SvRV(attrs)) != SVt_PVAV)
	   {
	      croak("Net::LDAPapi::ldap_search_st needs ARRAY reference as argument 5.");
	      XSRETURN(1);
	   }
	   if ((arraylen = av_len((AV *)SvRV(attrs))) < 0)
	   {
	      New(1,attrs_char,2,char *);
	      attrs_char[0] = NULL;
	   } else {
	      New(1,attrs_char,arraylen+2,char *);
	      for (count=0;count <= arraylen; count++)
	      {
		 current = av_fetch((AV *)SvRV(attrs),count,0);
		 attrs_char[count] = SvPV(*current,PL_na);
	      }
	      attrs_char[arraylen+1] = NULL;
	   }
	   if (timeout && *timeout)
	   {
	      tv_timeout = &timeoutbuf;
	      tv_timeout->tv_sec = atof(timeout);
	      tv_timeout->tv_usec = 0;
	   }
	   RETVAL = ldap_search_st(ld,base,scope,filter,attrs_char,attrsonly,
		tv_timeout,&res);
	   Safefree(attrs_char);
	}
	OUTPUT:
	RETVAL
	res

int
ldap_result(ld,msgid,all,timeout,result)
	LDAP *          ld
	int             msgid
	int             all
	LDAP_CHAR *     timeout
	LDAPMessage *   result = NO_INIT
	CODE:
	{
	   struct timeval *tv_timeout = NULL,timeoutbuf;
	   if (atof(timeout) > 0 && timeout && *timeout)
	   {
	      tv_timeout = &timeoutbuf;
	      tv_timeout->tv_sec = atof(timeout);
	      tv_timeout->tv_usec = 0;
	   }
	   RETVAL = ldap_result(ld,msgid,all,tv_timeout,&result);
	}
	OUTPUT:
	RETVAL
	result

int
ldap_msgfree(lm)
	LDAPMessage *   lm

void
ber_free(ber,freebuf)
	BerElement *ber
	int freebuf

#if defined(MOZILLA_LDAP) || defined(OPENLDAP)

int
ldap_msgid(lm)
	LDAPMessage *   lm

int
ldap_msgtype(lm)
	LDAPMessage *   lm

#else

int
ldap_msgid(lm)
	LDAPMessage *   lm
	CODE:
	{
	   RETVAL = lm->lm_msgid;
	}
	OUTPUT:
	RETVAL

int
ldap_msgtype(lm)
	LDAPMessage *   lm
	CODE:
	{
	   RETVAL = lm->lm_msgtype;
	}
	OUTPUT:
	RETVAL

#endif

#if defined(MOZILLA_LDAP)

int
ldap_get_lderrno(ld,m,s)
	LDAP *          ld
	char *          m = NO_INIT
	char *          s = NO_INIT
	CODE:
	{
	   RETVAL = ldap_get_lderrno(ld,&m,&s);
	}
	OUTPUT:
	RETVAL
	m
	s

int
ldap_set_lderrno(ld,e,m,s)
	LDAP *          ld
	int             e
	char *          m
	char *          s

#else

int
ldap_get_lderrno(ld,m,s)
	LDAP *          ld
	char *          m = NO_INIT
	char *          s = NO_INIT
	CODE:
	{
#ifdef OPENLDAP
	   ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &RETVAL);
	   ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &s);
	   ldap_get_option(ld, LDAP_OPT_MATCHED_DN, &m);
#else
	   RETVAL = ld->ld_errno;
	   m = ld->ld_matched;
	   s = ld->ld_error;
#endif
	}
	OUTPUT:
	RETVAL
	m
	s

int
ldap_set_lderrno(ld,e,m,s)
	LDAP *          ld
	int             e
	char *          m
	char *          s
	CODE:
	{
	   RETVAL = 0;
#ifdef OPENLDAP
	   ldap_set_option(ld, LDAP_OPT_ERROR_NUMBER, &e);
	   ldap_set_option(ld, LDAP_OPT_ERROR_STRING, s);
	   ldap_set_option(ld, LDAP_OPT_MATCHED_DN, m);
#else
	   ld->ld_errno = e;
	   ld->ld_matched = m;
	   ld->ld_error = s;
#endif
	}
	OUTPUT:
	RETVAL

#endif

int
ldap_result2error(ld,r,freeit)
	LDAP *          ld
	LDAPMessage *   r
	int             freeit

char *
ldap_err2string(err)
	int err

int
ldap_count_entries(ld,result)
	LDAP *          ld
	LDAPMessage *   result

LDAPMessage *
ldap_first_entry(ld,result)
	LDAP *          ld
	LDAPMessage *   result

LDAPMessage *
ldap_next_entry(ld,preventry)
	LDAP *          ld
	LDAPMessage *   preventry

SV *
ldap_get_dn(ld,entry)
	LDAP *          ld
	LDAPMessage *   entry
	PREINIT:
	   char * dn;
	CODE:
	{
	   dn = ldap_get_dn(ld, entry);
	   if (dn)
	   {
	      RETVAL = newSVpv(dn,0);
	      ldap_memfree(dn);
	   } else {
	      RETVAL = &PL_sv_undef;
	   }
	}
	OUTPUT:
	RETVAL

void
ldap_perror(ld,s)
	LDAP *          ld
	LDAP_CHAR *     s


char *
ldap_dn2ufn(dn)
	LDAP_CHAR *     dn

#if defined(MOZILLA_LDAP) || defined(OPENLDAP)

void
ldap_explode_dn(dn,notypes)
	char *          dn
	int             notypes
	PPCODE:
	{
	   char ** LDAPGETVAL;
	   int i;

	   if ((LDAPGETVAL = ldap_explode_dn(dn,notypes)) != NULL)
	   {
	       for (i = 0; LDAPGETVAL[i] != NULL; i++)
	       {
		  EXTEND(sp,1);
		  PUSHs(sv_2mortal(newSVpv(LDAPGETVAL[i],strlen(LDAPGETVAL[i]))));
	       }
	      ldap_value_free(LDAPGETVAL);
	   }
	}

void
ldap_explode_rdn(dn,notypes)
	char *          dn
	int     notypes
	PPCODE:
	{
	   char ** LDAPGETVAL;
	   int i;

	   if ((LDAPGETVAL = ldap_explode_rdn(dn,notypes)) != NULL)
	   {
	       for (i = 0; LDAPGETVAL[i] != NULL; i++)
	       {
		  EXTEND(sp,1);
		  PUSHs(sv_2mortal(newSVpv(LDAPGETVAL[i],strlen(LDAPGETVAL[i]))));
	       }
	      ldap_value_free(LDAPGETVAL);
	   }
	}

#ifdef MOZILLA_LDAP

void
ldap_explode_dns(dn)
	char *          dn
	PPCODE:
	{
	   char ** LDAPGETVAL;
	   int i;

	   if ((LDAPGETVAL = ldap_explode_dns(dn)) != NULL)
	   {
	       for (i = 0; LDAPGETVAL[i] != NULL; i++)
	       {
		  EXTEND(sp,1);
		  PUSHs(sv_2mortal(newSVpv(LDAPGETVAL[i],strlen(LDAPGETVAL[i]))));
	       }
	      ldap_value_free(LDAPGETVAL);
	   }
	}

#endif
#endif

SV *
ldap_first_attribute(ld,entry,ber)
	LDAP *          ld
	LDAPMessage *   entry
	BerElement *    ber = NO_INIT
	PREINIT:
	   char * attr;
	CODE:
	{
	   attr = ldap_first_attribute(ld,entry,&ber);
	   if (attr)
	   {
	      RETVAL = newSVpv(attr,0);
	      ldap_memfree(attr);
	   } else {
	      RETVAL = &PL_sv_undef;
	   }
	}
	OUTPUT:
	RETVAL
	ber

SV *
ldap_next_attribute(ld,entry,ber)
	LDAP *          ld
	LDAPMessage *   entry
	BerElement *    ber
	PREINIT:
	   char * attr;
	CODE:
	{
	   attr = ldap_next_attribute(ld,entry,ber);
	   if (attr)
	   {
	      RETVAL = newSVpv(attr,0);
	      ldap_memfree(attr);
	   } else {
	      RETVAL = &PL_sv_undef;
	   }
	}
	OUTPUT:
	RETVAL
	ber


void
ldap_get_values(ld,entry,attr)
	LDAP *          ld
	LDAPMessage *   entry
	char *          attr
	PPCODE:
	{
	   char ** LDAPGETVAL;
	   int i;

	   if ((LDAPGETVAL = ldap_get_values(ld,entry,attr)) != NULL)
	   {
	      for (i = 0; LDAPGETVAL[i] != NULL; i++)
	      {
	         EXTEND(sp,1);
	         PUSHs(sv_2mortal(newSVpv(LDAPGETVAL[i],strlen(LDAPGETVAL[i]))));
	      }
	      ldap_value_free(LDAPGETVAL);
	   }
	}

void
ldap_get_values_len(ld,entry,attr)
	LDAP *          ld
	LDAPMessage *   entry
	char *          attr
	PPCODE:
	{
	   struct berval ** LDAPGETVAL;
	   int i;

	   if ((LDAPGETVAL = ldap_get_values_len(ld,entry,attr)) != NULL)
	   {
	       for (i = 0; LDAPGETVAL[i] != NULL; i++)
	       {
		  EXTEND(sp,1);
		  PUSHs(sv_2mortal(newSVpv(LDAPGETVAL[i]->bv_val,LDAPGETVAL[i]->bv_len)));
	       }
	   }
	}

#ifdef MOZILLA_LDAP

int
ldapssl_client_init(certdbpath,certdbhandle)
	char *          certdbpath
	void *          certdbhandle

LDAP *
ldapssl_init(defhost,defport,defsecure)
	char *          defhost
	int             defport
	int             defsecure

int
ldapssl_install_routines(ld)
	LDAP *          ld

#endif

void
ldap_set_rebind_proc(ld,rebind_function,args)
	LDAP *          ld
	SV *            rebind_function
	void *		args
	CODE:
	{
	   if (SvTYPE(SvRV(rebind_function)) != SVt_PVCV)
	   {
#if defined(MOZILLA_LDAP) || defined(OPENLDAP)
	      ldap_set_rebind_proc(ld,NULL,NULL);
#else
	      ldap_set_rebind_proc(ld,NULL);
#endif
	   } else {
	      if (ldap_perl_rebindproc == (SV*)NULL)
	         ldap_perl_rebindproc = newSVsv(rebind_function);
	      else
	         SvSetSV(ldap_perl_rebindproc,rebind_function);
#if defined(MOZILLA_LDAP)
	      ldap_set_rebind_proc(ld,ns_internal_rebind_proc,args);
#else
	      ldap_set_rebind_proc(ld,internal_rebind_proc, args);
#endif
	   }
	}

HV *
ldap_get_all_entries(ld,result)
	LDAP *          ld
	LDAPMessage *   result
	CODE:
	{
	   LDAPMessage *entry = NULL;
	   char *dn = NULL, *attr = NULL;
	   struct berval **vals = NULL;
	   BerElement *ber = NULL;
	   int count = 0;
	   HV*   FullHash = newHV();

	   for ( entry = ldap_first_entry(ld, result); entry != NULL;
		entry = ldap_next_entry(ld, entry) )
	   {
	      HV* ResultHash = newHV();
	      SV* HashRef = newRV((SV*) ResultHash);

	      if ((dn = ldap_get_dn(ld, entry)) == NULL)
		 continue; 

	      for ( attr = ldap_first_attribute(ld, entry, &ber);
		  attr != NULL;
		  attr = ldap_next_attribute(ld, entry, ber) )
	      {

		 AV* AttributeValsArray = newAV();
		 SV* ArrayRef = newRV((SV*) AttributeValsArray);
		 if ((vals = ldap_get_values_len(ld, entry, attr)) != NULL)
		 {
		    for (count=0; vals[count] != NULL; count++)
		    {
		       SV* SVval = newSVpv(vals[count]->bv_val,vals[count]->bv_len);
		       av_push(AttributeValsArray, SVval);
		    }
		 }
		 hv_store(ResultHash, attr, strlen(attr), ArrayRef, 0);
	         if (vals != NULL)
		    ldap_value_free_len(vals);
	      }
	      if (attr != NULL)
	         ldap_memfree(attr);
	      hv_store(FullHash, dn, strlen(dn), HashRef, 0);
	      if (dn != NULL)
	         ldap_memfree(dn);
#if defined(MOZILLA_LDAP) || defined(OPENLDAP)
	      if (ber != NULL)
	         ber_free(ber,0);
#endif
	   }
	   RETVAL = FullHash;
	}
	OUTPUT:
	RETVAL

int
ldap_is_ldap_url(url)
	char *		url

SV *
ldap_url_parse(url)
	char *		url
	CODE:
	{
	   LDAPURLDesc *realcomp;
	   int count,ret;

	   HV*   FullHash = newHV();
	   RETVAL = newRV((SV*)FullHash);

	   ret = ldap_url_parse(url,&realcomp);
	   if (ret == 0)
	   {
	      static char *host_key = "host";
	      static char *port_key = "port";
	      static char *dn_key = "dn";
	      static char *attr_key = "attr";
	      static char *scope_key = "scope";
	      static char *filter_key = "filter";
#ifdef MOZILLA_LDAP
	      static char *options_key = "options";
	      SV* options = newSViv(realcomp->lud_options);
#endif
#ifdef OPENLDAP
	      static char *scheme_key = "scheme";
	      static char *exts_key = "exts";
	      AV* extsarray = newAV();
	      SV* extsibref = newRV((SV*) extsarray);
	      SV* scheme = newSVpv(realcomp->lud_scheme,0);
#endif
	      SV* host = newSVpv(realcomp->lud_host,0);
	      SV* port = newSViv(realcomp->lud_port);
	      SV* dn; /* = newSVpv(realcomp->lud_dn,0); */
	      SV* scope = newSViv(realcomp->lud_scope);
	      SV* filter = newSVpv(realcomp->lud_filter,0);
	      AV* attrarray = newAV();
	      SV* attribref = newRV((SV*) attrarray);

	      if (realcomp->lud_dn)
                 dn = newSVpv(realcomp->lud_dn,0);
	      else
	         dn = newSVpv("",0);

	      if (realcomp->lud_attrs != NULL)
	      {
	         for (count=0; realcomp->lud_attrs[count] != NULL; count++)
	         {
	            SV* SVval = newSVpv(realcomp->lud_attrs[count],0);
	            av_push(attrarray, SVval);
	         }
	      }
#ifdef OPENLDAP
	      if (realcomp->lud_exts != NULL)
	      {
	         for (count=0; realcomp->lud_exts[count] != NULL; count++)
	         {
	            SV* SVval = newSVpv(realcomp->lud_exts[count],0);
	            av_push(extsarray, SVval);
	         }
	      }
	      hv_store(FullHash,exts_key,strlen(exts_key),extsibref,0);
	      hv_store(FullHash,scheme_key,strlen(scheme_key),scheme,0);
#endif
	      hv_store(FullHash,host_key,strlen(host_key),host,0);
	      hv_store(FullHash,port_key,strlen(port_key),port,0);
	      hv_store(FullHash,dn_key,strlen(dn_key),dn,0);
	      hv_store(FullHash,attr_key,strlen(attr_key),attribref,0);
	      hv_store(FullHash,scope_key,strlen(scope_key),scope,0);
	      hv_store(FullHash,filter_key,strlen(filter_key),filter,0);
#ifdef MOZILLA_LDAP
	      hv_store(FullHash,options_key,strlen(options_key),options,0);
#endif
	      ldap_free_urldesc(realcomp);
	   } else {
	      RETVAL = &PL_sv_undef;
	   }
	}
	OUTPUT:
	RETVAL

#ifndef OPENLDAP

int
ldap_url_search(ld,url,attrsonly)
	LDAP *		ld
	char *		url
	int		attrsonly

int
ldap_url_search_s(ld,url,attrsonly,result)
	LDAP *		ld
	char *		url
	int		attrsonly
	LDAPMessage *	result = NO_INIT
	CODE:
	{
	   RETVAL = ldap_url_search_s(ld,url,attrsonly,&result);
	}
	OUTPUT:
	RETVAL
	result

int
ldap_url_search_st(ld,url,attrsonly,timeout,result)
	LDAP *		ld
	char *		url
	int		attrsonly
	LDAP_CHAR *	timeout
	LDAPMessage *	result = NO_INIT
	CODE:
	{
	   struct timeval *tv_timeout = NULL, timeoutbuf; 
	   if (timeout && *timeout)
	   {
	      tv_timeout = &timeoutbuf;
	      tv_timeout->tv_sec = atof(timeout);
	      tv_timeout->tv_usec = 0;
	   }
	   RETVAL = ldap_url_search_st(ld,url,attrsonly,tv_timeout,&result);
	}
	OUTPUT:
	RETVAL
	result

#endif
	
int
ldap_sort_entries(ld,chain,attr)
	LDAP *		ld
	LDAPMessage *	chain
	char *		attr
	CODE:
	{
	   RETVAL = ldap_sort_entries(ld,&chain,attr,StrCaseCmp);
	}
	OUTPUT:
	RETVAL
	chain

#ifdef MOZILLA_LDAP

int
ldap_multisort_entries(ld,chain,attrs)
	LDAP *		ld
	LDAPMessage *	chain
	SV *		attrs
	CODE:
	{
	   char **attrs_char;
	   SV ** current;
	   int count,arraylen;
           if (SvTYPE(SvRV(attrs)) == SVt_PVAV)
           {
              if ((arraylen = av_len((AV *)SvRV(attrs))) < 0)
              {
                 New(1,attrs_char,2,char *);
                 attrs_char[0] = NULL;
              } else {
                 New(1,attrs_char,arraylen+2,char *);
                 for (count=0;count <= arraylen; count++)
                 {
                    current = av_fetch((AV *)SvRV(attrs),count,0);
                    attrs_char[count] = SvPV(*current,PL_na);
                 }
                 attrs_char[arraylen+1] = NULL;
              }
           } else {
              croak("Net::LDAPapi::ldap_multisort_entries needs ARRAY reference as argument 3.");
              XSRETURN(1);
           }
	   RETVAL = ldap_multisort_entries(ld,&chain,attrs_char,StrCaseCmp);
	}
	OUTPUT:
	RETVAL
	chain

#endif

#ifdef OPENLDAP

int
ldap_start_tls_s(ld)
	LDAP *	ld
	CODE:
	{
	   RETVAL = ldap_start_tls_s(ld,NULL,NULL);
	}
	OUTPUT:
	RETVAL

int
ldap_sasl_interactive_bind_s(ld,who,passwd,mech,realm,authzid,props,flags)
	LDAP *	ld
	LDAP_CHAR *	who
	LDAP_CHAR *	passwd
	LDAP_CHAR *	mech
	LDAP_CHAR *	realm
	LDAP_CHAR *	authzid
	LDAP_CHAR *	props
	unsigned	flags
	CODE:
	{
	  	bictx ctx = {who, passwd, realm, authzid};
		if (props)
			ldap_set_option(ld,LDAP_OPT_X_SASL_SECPROPS,props);
		RETVAL = ldap_sasl_interactive_bind_s( ld, NULL, mech, NULL, NULL,
			flags, ldap_b2_interact, &ctx );
	}
	OUTPUT:
	RETVAL

#endif
