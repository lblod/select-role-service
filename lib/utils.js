import { sparqlEscapeUri, sparqlEscapeString } from "mu";
import { querySudo as query, updateSudo as update } from "@lblod/mu-auth-sudo";

export function getSessionIdHeader(request) {
    return request.get("mu-session-id");
}

/**
 * Get the rewrite URL from the request headers
 *
 * @return {string} The rewrite URL from the request headers
 */
export function getRewriteUrlHeader(request) {
    return request.get("x-rewrite-url");
}

/**
 * Helper function to return an error response
 */
export function error(res, message, status = 400) {
    return res.status(status).json({ errors: [{ title: message }] });
}

export async function getSessionRoles(session) {
    // prettier-ignore
    const queryResult = await query(`
        select distinct ?sessionRole where {
            graph <http://mu.semte.ch/graphs/sessions> {
                ${sparqlEscapeUri(session)} <http://mu.semte.ch/vocabularies/ext/sessionRole> ?sessionRole.
            }
        }
    `);
    const bindings = queryResult.results.bindings;
    if (bindings.length) {
        return bindings.map((b) => b.sessionRole.value);
    } else {
        return [];
    }
}

export async function updateActiveRole(session, role) {
    // prettier-ignore
    await update(`
        delete {
            graph <http://mu.semte.ch/graphs/sessions> {
                  ${sparqlEscapeUri(session)} <http://mu.semte.ch/vocabularies/ext/activeSessionRole> ?activeSessionRole.
            }
        }
        insert {
            graph <http://mu.semte.ch/graphs/sessions> {
                  ${sparqlEscapeUri(session)} <http://mu.semte.ch/vocabularies/ext/activeSessionRole> ${sparqlEscapeString(role)}.
            }
        }

        where {
            graph <http://mu.semte.ch/graphs/sessions> {
                  optional { ${sparqlEscapeUri(session)} <http://mu.semte.ch/vocabularies/ext/activeSessionRole> ?activeSessionRole }
            }
        }`);
}
export async function destroyActiveSessionRole(session) {
    // prettier-ignore
    await update(`
        delete where {
            graph <http://mu.semte.ch/graphs/sessions> {
                  ${sparqlEscapeUri(session)} <http://mu.semte.ch/vocabularies/ext/activeSessionRole> ?activeSessionRole.
            }
        }`);
}

export async function getActiveSessionRole(session) {
    // prettier-ignore
    const queryResult = await query(`
        select distinct ?activeSessionRole where {
            graph <http://mu.semte.ch/graphs/sessions> {
                ${sparqlEscapeUri(session)} <http://mu.semte.ch/vocabularies/ext/activeSessionRole> ?activeSessionRole.
            }
        }
    `);
    const bindings = queryResult.results.bindings;
    if (bindings.length != 1) {
        console.error(`bindings should be one: ${JSON.stringify(bindings)}`); // todo maybe just debug level
        throw Error(`Too many roles or no active role set`);
    }
    return bindings[0].activeSessionRole.value;
}
