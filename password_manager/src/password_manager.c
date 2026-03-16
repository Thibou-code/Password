#include <kore/kore.h>
#include <kore/http.h>
#include <kore/hooks.h>
#include <sqlite3.h>

sqlite3 *db = NULL;

int password_list(struct http_request *req); 
int password_generate(struct http_request *req);
int password_delete(struct http_request *req);

void kore_worker_configure(void)
{
    int rc = sqlite3_open("passwords.db", &db);
    if (rc != SQLITE_OK)
    {
        kore_log(LOG_ERR, "Impossible d'ouvrir la DB: %s", sqlite3_errmsg(db));
        return;
    }

    // Création de la table si elle n'existe pas
    char *sql = "CREATE TABLE IF NOT EXISTS passwords ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "site TEXT NOT NULL,"
                "password TEXT NOT NULL);";

    sqlite3_exec(db, sql, 0, 0, NULL);
    kore_log(LOG_INFO, "Base de données SQLite prête.");
}

int password_list(struct http_request *req) 
{
    struct kore_json_item *root, *array, *obj;
    sqlite3_stmt          *stmt;
    char                  *filter_site;
    struct kore_buf       buf;

    http_populate_get(req);
    int has_filter = http_argument_get_string(req, "site", &filter_site);

    // Construction JSON : racine = objet, pas besoin de kore_json_init
    root  = kore_json_create_object(NULL, NULL);
    array = kore_json_create_array(root, "passwords");

    const char *sql = has_filter
        ? "SELECT id, site, password FROM passwords WHERE site LIKE ?"
        : "SELECT id, site, password FROM passwords";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        kore_log(LOG_ERR, "sqlite3_prepare_v2: %s", sqlite3_errmsg(db));
        http_response(req, 500, NULL, 0);
        kore_json_item_free(root);
        return (KORE_RESULT_OK);
    }

    if (has_filter) {
        char *query = kore_malloc(strlen(filter_site) + 3);
        sprintf(query, "%%%s%%", filter_site);
        sqlite3_bind_text(stmt, 1, query, -1, kore_free);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // Les items d'un array ont NULL comme nom
        obj = kore_json_create_object(array, NULL);
        kore_json_create_integer(obj, "id",       sqlite3_column_int(stmt, 0));
        kore_json_create_string(obj,  "site",     (const char *)sqlite3_column_text(stmt, 1));
        kore_json_create_string(obj,  "password", (const char *)sqlite3_column_text(stmt, 2));
    }

    kore_buf_init(&buf, 1024);
    kore_json_item_tobuf(root, &buf);

    http_response_header(req, "content-type", "application/json");
    http_response(req, 200, buf.data, buf.offset);

    kore_buf_cleanup(&buf);
    kore_json_item_free(root);   // libère tout l'arbre JSON
    sqlite3_finalize(stmt);

    return (KORE_RESULT_OK);
}

int password_generate(struct http_request *req)
{
    // TODO
    return 0;
}

int password_delete(struct http_request *req)
{
    // TODO
    return 0;
}