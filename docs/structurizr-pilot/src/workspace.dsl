workspace "WebAuthn Kotlin Multiplatform" "Architecture views for the library repository." {
    !identifiers hierarchical

    model {
        applicationDeveloper = person "Application developer" "Builds a Kotlin application with the library."

        webauthnLibrary = softwareSystem "WebAuthn Kotlin Multiplatform" "Multiplatform WebAuthn protocol library." {
            protocolModel = container "Protocol model" "Public WebAuthn data types and serialisation boundary." "Kotlin Multiplatform"
            coreFoundation = container "Core foundation" "Shared WebAuthn primitives, validation, and utilities." "Kotlin Multiplatform"
            crypto = container "Cryptography" "WebAuthn cryptographic primitives and platform implementations." "Kotlin Multiplatform"
            server = container "Server support" "Server-side ceremonies, stores, and Ktor integration." "Kotlin/JVM"
            client = container "Client support" "Android, Compose, iOS, and core client APIs." "Kotlin Multiplatform"

            coreFoundation -> protocolModel "Uses protocol types"
            crypto -> coreFoundation "Builds on primitives"
            crypto -> protocolModel "Serialises keys and algorithms"
            server -> coreFoundation "Runs ceremonies"
            server -> crypto "Verifies assertions"
            server -> protocolModel "Exposes request/response types"
            client -> coreFoundation "Builds requests"
            client -> crypto "Uses client crypto"
            client -> protocolModel "Exposes platform APIs"
        }

        relyingParty = softwareSystem "Relying party" "Application backend that performs registration and authentication ceremonies."
        authenticator = softwareSystem "Authenticator / platform passkey API" "Browser, OS, or security key WebAuthn implementation."
        metadataService = softwareSystem "Attestation metadata service" "Authenticates and classifies attestation statements."

        applicationDeveloper -> webauthnLibrary "Integrates"
        relyingParty -> webauthnLibrary.server "Uses"
        relyingParty -> webauthnLibrary.client "Uses when sharing client code"
        webauthnLibrary.server -> authenticator "Verifies WebAuthn output from"
        webauthnLibrary.client -> authenticator "Invokes"
        webauthnLibrary.server -> metadataService "Consults for attestation"
    }

    views {
        systemContext webauthnLibrary "system_context" "Library adopters and external WebAuthn context." {
            include *
            autoLayout lr 300 200
        }

        container webauthnLibrary "repository_overview" "Five responsibility layers and their primary dependencies." {
            include *
            exclude applicationDeveloper
            exclude relyingParty
            exclude authenticator
            exclude metadataService
            autoLayout tb 300 200
        }

        container webauthnLibrary "core_dependencies" "Focused core and cryptography dependency slice." {
            include webauthnLibrary.coreFoundation
            include webauthnLibrary.crypto
            include webauthnLibrary.protocolModel
            autoLayout lr 300 200
        }

        styles {
            element "Person" {
                shape person
                background #1f4e79
                color #ffffff
            }
            element "Software System" {
                background #0b6e99
                color #ffffff
            }
            element "Container" {
                background #2a9d8f
                color #ffffff
            }
            relationship "Relationship" {
                color #5f6b7a
                thickness 2
            }
        }
    }
}
