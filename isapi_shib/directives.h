#define SHIB_REG_KEY "Software\\Internet2\\Shibboleth"
#define SHIB_DEFAULT_WEB_KEY "Software\\Internet 2\\Shibboleth\\Webs\\default"
#define D_FREE_STRING 0
#define D_FREE_INT 1
#define D_BOUND_INT 2
#define D_BOUND_STRING 3
#define MAX_REG_BUFF 4096 // Using a fixed size saves a registy lookup and malloc 
#define MAX_DIRECTIVE_STRING 256 // Set to lagest size of default strings below

#define NUM_DIRECTIVES 2  // Set to number of directives below
#define NUM_BOUND_VAL 2   // Set to maximum number of bound values 

struct directives_t {
	char name[MAX_DIRECTIVE_STRING];
	unsigned short type;
	char value[MAX_DIRECTIVE_STRING];
	char description[MAX_DIRECTIVE_STRING];
	char defined_in[MAX_DIRECTIVE_STRING];
	char bound_val[NUM_BOUND_VAL][MAX_DIRECTIVE_STRING];
};

const directives_t directives[] = {
	{
#       define DIRECTIVE_AUTHTYPE 0				// defines make code more readable than enum 
		"AuthType",								// name
		D_FREE_STRING,							// type
		"None",									// default value.  Case insensitive.
		"Use Shibboleth to enable Shibboleth. Any other value disables Shibboleth.\nIf no value specified," \
		" the MustContain string will be searched for in the target URL.", // description
		"(Program Default)",					// default value for defined_in
		"",										// possible bound value 
		""                                      // possible bound value
	},
	{
#       define DIRECTIVE_SSL_ONLY 1             // Example only, not implemented in filter
		"ShibSSLOnly",
		D_BOUND_STRING,
		"Off",
		"Controls whether Shibboleth will reject non-SSL requests for resources from clients.",
		"(Program Default)",
		"On",
		"Off"

	}
};