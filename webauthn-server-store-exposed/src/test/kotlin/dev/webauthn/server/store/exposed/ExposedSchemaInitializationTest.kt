package dev.webauthn.server.store.exposed

import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.SchemaUtils
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ExposedSchemaInitializationTest {
    @Test
    fun `initializeWebAuthnSchema creates schema for an empty database`() {
        val database = createDatabase()

        initializeWebAuthnSchema(database)

        assertTrue(webAuthnSchemaMigrationStatements(database).isEmpty())
    }

    @Test
    fun `validateWebAuthnSchema succeeds after schema creation`() {
        val database = createDatabase()
        initializeWebAuthnSchema(database)

        validateWebAuthnSchema(database)
    }

    @Test
    fun `initializeWebAuthnSchema fails when an existing schema needs migration`() {
        val database = createDatabase()
        transaction(database) {
            SchemaUtils.create(ChallengeSessions)
        }

        assertFailsWith<IllegalStateException> {
            initializeWebAuthnSchema(database)
        }

        assertTrue(
            webAuthnSchemaMigrationStatements(database).any {
                it.contains("create table", ignoreCase = true)
            }
        )
    }

    @Test
    fun `validateWebAuthnSchema reports migration statements for an uninitialized schema`() {
        val database = createDatabase()

        assertFailsWith<IllegalStateException> {
            validateWebAuthnSchema(database)
        }

        assertTrue(
            webAuthnSchemaMigrationStatements(database).any {
                it.contains("create table", ignoreCase = true)
            }
        )
    }

    private fun createDatabase(): Database =
        Database.connect(
            url = "jdbc:h2:mem:${java.util.UUID.randomUUID()};DB_CLOSE_DELAY=-1",
            driver = "org.h2.Driver",
        )
}
