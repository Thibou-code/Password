#include <kore/kore.h>
#include <kore/http.h>
#include <kore/hooks.h>
#include <sqlite3.h>

#define PASSWORD_CHARS           \
    "abcdefghijklmnopqrstuvwxyz" \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
    "0123456789"                 \
    "!@#$%^&*()-_=+[]{}?"

#define PASSWORD_CHARS_LEN 84
#define PASSWORD_DEFAULT_LEN 16
#define PASSWORD_MAX_LEN 64

sqlite3 *db = NULL;

int password_list(struct http_request *req);
int password_generate(struct http_request *req);
int password_delete(struct http_request *req);

static void generate_password(char *out, int length)
{
    for (int i = 0; i < length; i++)
        out[i] = PASSWORD_CHARS[arc4random_uniform(PASSWORD_CHARS_LEN)];
    out[length] = '\0';
}

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
    sqlite3_stmt *stmt;
    char *filter_site;
    struct kore_buf buf;

    http_populate_get(req);
    int has_filter = http_argument_get_string(req, "site", &filter_site);

    // Construction JSON : racine = objet, pas besoin de kore_json_init
    root = kore_json_create_object(NULL, NULL);
    array = kore_json_create_array(root, "passwords");

    const char *sql = has_filter
                          ? "SELECT id, site, password FROM passwords WHERE site LIKE ?"
                          : "SELECT id, site, password FROM passwords";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        kore_log(LOG_ERR, "sqlite3_prepare_v2: %s", sqlite3_errmsg(db));
        http_response(req, 500, NULL, 0);
        kore_json_item_free(root);
        return (KORE_RESULT_OK);
    }

    if (has_filter)
    {
        char *query = kore_malloc(strlen(filter_site) + 3);
        sprintf(query, "%%%s%%", filter_site);
        sqlite3_bind_text(stmt, 1, query, -1, kore_free);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        // Les items d'un array ont NULL comme nom
        obj = kore_json_create_object(array, NULL);
        kore_json_create_integer(obj, "id", sqlite3_column_int(stmt, 0));
        kore_json_create_string(obj, "site", (const char *)sqlite3_column_text(stmt, 1));
        kore_json_create_string(obj, "password", (const char *)sqlite3_column_text(stmt, 2));
    }

    kore_buf_init(&buf, 1024);
    kore_json_item_tobuf(root, &buf);

    http_response_header(req, "content-type", "application/json");
    http_response(req, 200, buf.data, buf.offset);

    kore_buf_cleanup(&buf);
    kore_json_item_free(root);
    sqlite3_finalize(stmt);

    return (KORE_RESULT_OK);
}

int password_generate(struct http_request *req)
{
    struct kore_json json;
    struct kore_json_item *root, *obj, *site, *lengthPt;
    char password[PASSWORD_MAX_LEN + 1];
    struct kore_buf buf;
    sqlite3_stmt *stmt;
    u_int8_t *body;
    int64_t pw_length = PASSWORD_DEFAULT_LEN;
    ssize_t body_len;

    // Lire le body de la requête
    if (req->http_body_length == 0)
    {
        http_response(req, 400, NULL, 0);
        return (KORE_RESULT_OK);
    }

    body = kore_malloc(req->http_body_length);

    body_len = http_body_read(req, body, req->http_body_length);

    // Parser le JSON du body pour qu'il soit manipulable par le framework
    kore_json_init(&json, body, (size_t)body_len);
    if (!kore_json_parse(&json))
    {
        kore_log(LOG_ERR, "JSON invalide: %s", kore_json_strerror());
        http_response(req, 400, NULL, 0);
        kore_json_cleanup(&json);
        return (KORE_RESULT_OK);
    }

    // Récupérer le champ "site" 
    site = kore_json_find_string(json.root, "site");
    if (site == NULL)
    {
        http_response(req, 400, "\"site\" requis", 13);
        kore_json_cleanup(&json);
        return (KORE_RESULT_OK);
    }

    // Récupérer "length" (optionnel)
    lengthPt = kore_json_find_integer(json.root, "length");
    if (lengthPt != NULL && lengthPt->data.integer >= 8 && lengthPt->data.integer <= PASSWORD_MAX_LEN)
        pw_length = lengthPt->data.integer;

    // Générer le mot de passe
    generate_password(password,  (int)pw_length);

    // Sauvegarder en base
    if (sqlite3_prepare_v2(db,
                           "INSERT INTO passwords (site, password) VALUES (?, ?)",
                           -1, &stmt, NULL) != SQLITE_OK)
    {
        kore_log(LOG_ERR, "sqlite3_prepare: %s", sqlite3_errmsg(db));
        http_response(req, 500, NULL, 0);
        kore_json_cleanup(&json);
        return (KORE_RESULT_OK);
    }

    sqlite3_bind_text(stmt, 1, site->data.string, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        kore_log(LOG_ERR, "sqlite3_step: %s", sqlite3_errmsg(db));
        http_response(req, 500, NULL, 0);
        sqlite3_finalize(stmt);
        kore_json_cleanup(&json);
        return (KORE_RESULT_OK);
    }

    sqlite3_int64 new_id = sqlite3_last_insert_rowid(db);
    sqlite3_finalize(stmt);

    // Construire la réponse JSON
    root = kore_json_create_object(NULL, NULL);
    obj = kore_json_create_object(root, "password");
    kore_json_create_integer(obj, "id", new_id);
    kore_json_create_string(obj, "site", site->data.string);
    kore_json_create_string(obj, "password", password);

    kore_buf_init(&buf, 256);
    kore_json_item_tobuf(root, &buf);

    http_response_header(req, "content-type", "application/json");
    http_response(req, 201, buf.data, buf.offset);

    kore_buf_cleanup(&buf);
    kore_json_item_free(root);
    kore_json_cleanup(&json);
    kore_free(body);

    return (KORE_RESULT_OK);
}

int password_delete(struct http_request *req)
{
    // TODO
    return 0;
}