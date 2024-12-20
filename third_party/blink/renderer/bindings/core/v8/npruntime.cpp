/*
 * Copyright (C) 2004, 2006 Apple Computer, Inc.  All rights reserved.
 * Copyright (C) 2007-2009 Google, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/bindings/core/v8/NPV8Object.h"
#include "third_party/blink/renderer/bindings/core/v8/V8NPObject.h"
#include "third_party/blink/renderer/bindings/core/v8/npruntime_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/npruntime_priv.h"

#include "third_party/blink/renderer/platform/wtf/assertions.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/hash_table_deleted_value_type.h"

#include <stdlib.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wheader-hygiene"
using namespace blink;
#pragma clang diagnostic pop

// FIXME: Consider removing locks if we're singlethreaded already.
// The static initializer here should work okay, but we want to avoid
// static initialization in general.

namespace npruntime {

// We use StringKey here as the key-type to avoid a string copy to
// construct the map key and for faster comparisons than strcmp.
class StringKey {
public:
    explicit StringKey(const char* str) : m_string(str), m_length(strlen(str)) { }
    StringKey() : m_string(0), m_length(0) { }
    explicit StringKey(WTF::HashTableDeletedValueType) : m_string(hashTableDeletedValue()), m_length(0) { }

    StringKey& operator=(const StringKey& other)
    {
        this->m_string = other.m_string;
        this->m_length = other.m_length;
        return *this;
    }

    bool isHashTableDeletedValue() const
    {
        return m_string == hashTableDeletedValue();
    }

    const char* m_string;
    size_t m_length;

private:
    const char* hashTableDeletedValue() const
    {
        return reinterpret_cast<const char*>(-1);
    }
};

inline bool operator==(const StringKey& x, const StringKey& y)
{
    if (x.m_length != y.m_length)
        return false;
    if (x.m_string == y.m_string)
        return true;

    DCHECK(!x.isHashTableDeletedValue() && !y.isHashTableDeletedValue());
    return !memcmp(x.m_string, y.m_string, y.m_length);
}

// Implement WTF::DefaultHash<StringKey>::Hash interface.
struct StringKeyHash {
    static unsigned GetHash(const StringKey& key)
    {
        // Compute string hash.
        unsigned hash = 0;
        size_t len = key.m_length;
        const char* str = key.m_string;
        for (size_t i = 0; i < len; i++) {
            char c = str[i];
            hash += c;
            hash += (hash << 10);
            hash ^= (hash >> 6);
        }
        hash += (hash << 3);
        hash ^= (hash >> 11);
        hash += (hash << 15);
        if (hash == 0)
            hash = 27;
        return hash;
    }

    static bool Equal(const StringKey& x, const StringKey& y)
    {
        return x == y;
    }

    static const bool safe_to_compare_to_empty_or_deleted = true;
};

}  // namespace npruntime

using npruntime::StringKey;
using npruntime::StringKeyHash;

// Implement HashTraits<StringKey>
struct StringKeyHashTraits : WTF::GenericHashTraits<StringKey> {
    static void ConstructDeletedValue(StringKey& slot, bool)
    {
        new (&slot) StringKey(WTF::kHashTableDeletedValue);
    }

    static bool IsDeletedValue(const StringKey& value)
    {
        return value.isHashTableDeletedValue();
    }
};

typedef WTF::HashMap<StringKey, PrivateIdentifier*, StringKeyHash, StringKeyHashTraits> StringIdentifierMap;

static StringIdentifierMap* getStringIdentifierMap()
{
    static StringIdentifierMap* stringIdentifierMap = 0;
    if (!stringIdentifierMap)
        stringIdentifierMap = new StringIdentifierMap();
    return stringIdentifierMap;
}

typedef WTF::HashMap<int, PrivateIdentifier*> IntIdentifierMap;

static IntIdentifierMap* getIntIdentifierMap()
{
    static IntIdentifierMap* intIdentifierMap = 0;
    if (!intIdentifierMap)
        intIdentifierMap = new IntIdentifierMap();
    return intIdentifierMap;
}

extern "C" {

NPIdentifier _NPN_GetStringIdentifier(const NPUTF8* name)
{
    DCHECK(name);

    if (name) {

        StringKey key(name);
        StringIdentifierMap* identMap = getStringIdentifierMap();
        StringIdentifierMap::iterator iter = identMap->find(key);
        if (iter != identMap->end())
            return static_cast<NPIdentifier>(iter->value);

        size_t nameLen = key.m_length;

        // We never release identifiers, so this dictionary will grow.
        PrivateIdentifier* identifier = static_cast<PrivateIdentifier*>(malloc(sizeof(PrivateIdentifier) + nameLen + 1));
        char* nameStorage = reinterpret_cast<char*>(identifier + 1);
        memcpy(nameStorage, name, nameLen + 1);
        identifier->isString = true;
        identifier->value.string = reinterpret_cast<NPUTF8*>(nameStorage);
        key.m_string = nameStorage;
        identMap->Set(key, identifier);
        return (NPIdentifier)identifier;
    }

    return 0;
}

void _NPN_GetStringIdentifiers(const NPUTF8** names, int32_t nameCount, NPIdentifier* identifiers)
{
    DCHECK(names);
    DCHECK(identifiers);

    if (names && identifiers) {
        for (int i = 0; i < nameCount; i++)
            identifiers[i] = _NPN_GetStringIdentifier(names[i]);
    }
}

NPIdentifier _NPN_GetIntIdentifier(int32_t intId)
{
    // Special case for -1 and 0, both cannot be used as key in HashMap.
    if (!intId || intId == -1) {
        static PrivateIdentifier* minusOneOrZeroIds[2];
        PrivateIdentifier* id = minusOneOrZeroIds[intId + 1];
        if (!id) {
            id = reinterpret_cast<PrivateIdentifier*>(malloc(sizeof(PrivateIdentifier)));
            id->isString = false;
            id->value.number = intId;
            minusOneOrZeroIds[intId + 1] = id;
        }
        return (NPIdentifier) id;
    }

    IntIdentifierMap* identMap = getIntIdentifierMap();
    IntIdentifierMap::iterator iter = identMap->find(intId);
    if (iter != identMap->end())
        return static_cast<NPIdentifier>(iter->value);

    // We never release identifiers, so this dictionary will grow.
    PrivateIdentifier* identifier = reinterpret_cast<PrivateIdentifier*>(malloc(sizeof(PrivateIdentifier)));
    identifier->isString = false;
    identifier->value.number = intId;
    identMap->Set(intId, identifier);
    return (NPIdentifier)identifier;
}

bool _NPN_IdentifierIsString(NPIdentifier identifier)
{
    PrivateIdentifier* privateIdentifier = reinterpret_cast<PrivateIdentifier*>(identifier);
    return privateIdentifier->isString;
}

NPUTF8 *_NPN_UTF8FromIdentifier(NPIdentifier identifier)
{
    PrivateIdentifier* privateIdentifier = reinterpret_cast<PrivateIdentifier*>(identifier);
    if (!privateIdentifier->isString || !privateIdentifier->value.string)
        return 0;

    return (NPUTF8*) strdup(privateIdentifier->value.string);
}

int32_t _NPN_IntFromIdentifier(NPIdentifier identifier)
{
    PrivateIdentifier* privateIdentifier = reinterpret_cast<PrivateIdentifier*>(identifier);
    if (privateIdentifier->isString)
        return 0;
    return privateIdentifier->value.number;
}

void _NPN_ReleaseVariantValue(NPVariant* variant)
{
    DCHECK(variant);

    if (variant->type == NPVariantType_Object) {
        _NPN_ReleaseObject(variant->value.objectValue);
        variant->value.objectValue = 0;
    } else if (variant->type == NPVariantType_String) {
        free((void*)variant->value.stringValue.UTF8Characters);
        variant->value.stringValue.UTF8Characters = 0;
        variant->value.stringValue.UTF8Length = 0;
    }

    variant->type = NPVariantType_Void;
}

NPObject *_NPN_CreateObject(NPP npp, NPClass* npClass)
{
    DCHECK(npClass);

    if (npClass) {
        NPObject* npObject;
        if (npClass->allocate != 0)
            npObject = npClass->allocate(npp, npClass);
        else
            npObject = reinterpret_cast<NPObject*>(malloc(sizeof(NPObject)));

        npObject->_class = npClass;
        npObject->referenceCount = 1;
        return npObject;
    }

    return 0;
}

NPObject* _NPN_RetainObject(NPObject* npObject)
{
    DCHECK(npObject);
    DCHECK(npObject->referenceCount > 0);

    if (npObject)
        npObject->referenceCount++;

    return npObject;
}

// _NPN_DeallocateObject actually deletes the object.  Technically,
// callers should use _NPN_ReleaseObject.  Webkit exposes this function
// to kill objects which plugins may not have properly released.
void _NPN_DeallocateObject(NPObject* npObject)
{
    DCHECK(npObject);

    if (npObject) {
        // NPObjects that remain in pure C++ may never have wrappers.
        // Hence, if it's not already alive, don't unregister it.
        // If it is alive, unregister it as the *last* thing we do
        // so that it can do as much cleanup as possible on its own.
        if (_NPN_IsAlive(npObject))
            _NPN_UnregisterObject(npObject);

        npObject->referenceCount = 0xFFFFFFFF;
        if (npObject->_class->deallocate)
            npObject->_class->deallocate(npObject);
        else
            free(npObject);
    }
}

void _NPN_ReleaseObject(NPObject* npObject)
{
    DCHECK(npObject);
    DCHECK(npObject->referenceCount >= 1);

    if (npObject && npObject->referenceCount >= 1) {
        if (!--npObject->referenceCount)
            _NPN_DeallocateObject(npObject);
    }
}

void _NPN_InitializeVariantWithStringCopy(NPVariant* variant, const NPString* value)
{
    variant->type = NPVariantType_String;
    variant->value.stringValue.UTF8Length = value->UTF8Length;
    variant->value.stringValue.UTF8Characters = reinterpret_cast<NPUTF8*>(malloc(sizeof(NPUTF8) * value->UTF8Length));
    memcpy((void*)variant->value.stringValue.UTF8Characters, value->UTF8Characters, sizeof(NPUTF8) * value->UTF8Length);
}

} // extern "C"

// NPN_Registry
//
// The registry is designed for quick lookup of NPObjects.
// JS needs to be able to quickly lookup a given NPObject to determine
// if it is alive or not.
// The browser needs to be able to quickly lookup all NPObjects which are
// "owned" by an object.
//
// The liveObjectMap is a hash table of all live objects to their owner
// objects.  Presence in this table is used primarily to determine if
// objects are live or not.
//
// The rootObjectMap is a hash table of root objects to a set of
// objects that should be deactivated in sync with the root.  A
// root is defined as a top-level owner object.  This is used on
// LocalFrame teardown to deactivate all objects associated
// with a particular plugin.

typedef WTF::HashSet<NPObject*> NPObjectSet;
typedef WTF::HashMap<NPObject*, NPObject*> NPObjectMap;
typedef WTF::HashMap<NPObject*, NPObjectSet*> NPRootObjectMap;

// A map of live NPObjects with pointers to their Roots.
static NPObjectMap& liveObjectMap()
{
    DEFINE_STATIC_LOCAL(NPObjectMap, objectMap, ());
    return objectMap;
}

// A map of the root objects and the list of NPObjects
// associated with that object.
static NPRootObjectMap& rootObjectMap()
{
    DEFINE_STATIC_LOCAL(NPRootObjectMap, objectMap, ());
    return objectMap;
}

extern "C" {

void _NPN_RegisterObject(NPObject* npObject, NPObject* owner)
{
    DCHECK(npObject);

    // Check if already registered.
    if (liveObjectMap().find(npObject) != liveObjectMap().end())
        return;

    if (!owner) {
        // Registering a new owner object.
        DCHECK(rootObjectMap().find(npObject) == rootObjectMap().end());
        rootObjectMap().Set(npObject, new NPObjectSet());
    } else {
        // Always associate this object with it's top-most parent.
        // Since we always flatten, we only have to look up one level.
        NPObjectMap::iterator ownerEntry = liveObjectMap().find(owner);
        NPObject* parent = 0;
        if (liveObjectMap().end() != ownerEntry)
            parent = ownerEntry->value;

        if (parent)
            owner = parent;
        DCHECK(rootObjectMap().find(npObject) == rootObjectMap().end());
        if (rootObjectMap().find(owner) != rootObjectMap().end())
            rootObjectMap().at(owner)->insert(npObject);
    }

    DCHECK(liveObjectMap().find(npObject) == liveObjectMap().end());
    liveObjectMap().Set(npObject, owner);
}

void _NPN_UnregisterObject(NPObject* npObject)
{
    DCHECK(npObject);
    SECURITY_DCHECK(liveObjectMap().find(npObject) != liveObjectMap().end());

    NPObject* owner = 0;
    if (liveObjectMap().find(npObject) != liveObjectMap().end())
        owner = liveObjectMap().find(npObject)->value;

    if (!owner) {
        // Unregistering a owner object; also unregister it's descendants.
        SECURITY_DCHECK(rootObjectMap().find(npObject) != rootObjectMap().end());
        NPObjectSet* set = rootObjectMap().at(npObject);
        while (set->size() > 0) {
            unsigned size = set->size();
            NPObject* sub_object = *(set->begin());
            // The sub-object should not be a owner!
            DCHECK(rootObjectMap().find(sub_object) == rootObjectMap().end());

            // First, unregister the object.
            set->erase(sub_object);
            liveObjectMap().erase(sub_object);

            // Script objects hold a refernce to their LocalDOMWindow*, which is going away if
            // we're unregistering the associated owner NPObject. Clear it out.
            if (V8NPObject* v8npObject = npObjectToV8NPObject(sub_object))
                v8npObject->rootObject = 0;

            // Remove the JS references to the object.
            forgetV8ObjectForNPObject(sub_object);

            DCHECK(set->size() < size);
        }
        delete set;
        rootObjectMap().erase(npObject);
    } else {
        NPRootObjectMap::iterator ownerEntry = rootObjectMap().find(owner);
        if (ownerEntry != rootObjectMap().end()) {
            NPObjectSet* list = ownerEntry->value;
            DCHECK(list->find(npObject) != list->end());
            list->erase(npObject);
        }
    }

    liveObjectMap().erase(npObject);
    forgetV8ObjectForNPObject(npObject);
}

bool _NPN_IsAlive(NPObject* npObject)
{
    return liveObjectMap().find(npObject) != liveObjectMap().end();
}

} // extern "C"
