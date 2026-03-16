#include <kore/kore.h>
#include <kore/http.h>
#include <sqlite3.h>

int		page(struct http_request *);

int
page(struct http_request *req)
{
	http_response(req, 200, NULL, 0);
	return (KORE_RESULT_OK);
}
