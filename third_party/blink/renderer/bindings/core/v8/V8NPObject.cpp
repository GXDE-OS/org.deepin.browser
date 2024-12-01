/*
* Copyright (C) 2006, 2007, 2008, 2009 Google Inc. All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
*     * Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above
* copyright notice, this list of conditions and the following disclaimer
* in the documentation and/or other materials provided with the
* distribution.
*     * Neither the name of Google Inc. nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "base/logging.h"
#include "build/build_config.h"
#include "third_party/blink/renderer/bindings/core/v8/V8NPObject.h"
#include "third_party/blink/renderer/bindings/core/v8/NPV8Object.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_map.h"
#include "third_party/blink/renderer/platform/bindings/shared_persistent.h"
#include "third_party/blink/renderer/platform/bindings/v8_global_value_map.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_html_applet_element.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_html_embed_element.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_html_object_element.h"
#include "third_party/blink/renderer/bindings/core/v8/V8NPUtils.h"
#include "third_party/blink/renderer/platform/bindings/v8_object_constructor.h"
#include "third_party/blink/renderer/bindings/core/v8/npruntime_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/npruntime_priv.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/public/web/WebBindings.h"
#include "v8-util.h"

namespace blink {

enum InvokeFunctionType {
    InvokeMethod = 1,
    InvokeConstruct = 2,
    InvokeDefault = 3
};

struct IdentifierRep {
    int number() const { return m_isString ? 0 : m_value.m_number; }
    const char* string() const { return m_isString ? m_value.m_string : 0; }

    union {
        const char* m_string;
        int m_number;
    } m_value;
    bool m_isString;
};

// FIXME: need comments.
// Params: holder could be HTMLEmbedElement or NPObject
static void npObjectInvokeImpl(const v8::FunctionCallbackInfo<v8::Value>& info, InvokeFunctionType functionId)
{
    NPObject* npObject;
    v8::Isolate* isolate = info.GetIsolate();

#if defined(USE_UNIONTECH_NPAPI)  // AP_PLUGINS
    // These three types are subtypes of HTMLPlugInElement.
    HTMLPlugInElement* element = V8HTMLAppletElement::ToImplWithTypeCheck(isolate, info.Holder());
    if (!element) {
        element = V8HTMLEmbedElement::ToImplWithTypeCheck(isolate, info.Holder());
        if (!element) {
            element = V8HTMLObjectElement::ToImplWithTypeCheck(isolate, info.Holder());
        }
    }
#else
    // These two types are subtypes of HTMLPlugInElement.
    HTMLPlugInElement* element = V8HTMLEmbedElement::ToImplWithTypeCheck(isolate, info.Holder());
    if (!element)
        element = V8HTMLObjectElement::ToImplWithTypeCheck(isolate, info.Holder());
#endif
    if (element) {
        v8::Local<v8::Object> wrapper = element->PluginWrapper(isolate);
        if (!wrapper.IsEmpty()) {
            v8::HandleScope handleScope(isolate);
            npObject = v8ObjectToNPObject(wrapper);
        } else {
            npObject = 0;
        }
    } else {
        // The holder object is not a subtype of HTMLPlugInElement, it must be an NPObject which has three
        // internal fields.
        if (info.Holder()->InternalFieldCount() != npObjectInternalFieldCount) {
            V8ThrowException::ThrowReferenceError(info.GetIsolate(), "NPMethod called on non-NPObject");
            return;
        }

        npObject = v8ObjectToNPObject(info.Holder());
    }

    // Verify that our wrapper wasn't using a NPObject which has already been deleted.
    if (!npObject || !_NPN_IsAlive(npObject)) {
        V8ThrowException::ThrowReferenceError(isolate, "NPObject deleted");
        return;
    }

    // Wrap up parameters.
    int numArgs = info.Length();
    std::unique_ptr<NPVariant[]> npArgs = std::make_unique<NPVariant[]>(numArgs);

    for (int i = 0; i < numArgs; i++)
        convertV8ObjectToNPVariant(isolate, info[i], npObject, &npArgs[i]);

    NPVariant result;
    VOID_TO_NPVARIANT(result);

    bool retval = true;
    switch (functionId) {
    case InvokeMethod:
        if (npObject->_class->invoke) {
            v8::Local<v8::String> functionName = v8::Local<v8::String>::Cast(info.Data());
            NPIdentifier identifier = getStringIdentifier(isolate, functionName);
            retval = npObject->_class->invoke(npObject, identifier, npArgs.get(), numArgs, &result);
        }
        break;
    case InvokeConstruct:
        if (npObject->_class->construct)
            retval = npObject->_class->construct(npObject, npArgs.get(), numArgs, &result);
        break;
    case InvokeDefault:
        if (npObject->_class->invokeDefault)
            retval = npObject->_class->invokeDefault(npObject, npArgs.get(), numArgs, &result);
        break;
    default:
        break;
    }

    if (!retval) {
        V8ThrowException::ThrowError(isolate, "Error calling method on NPObject.");
    }

    for (int i = 0; i < numArgs; i++)
        _NPN_ReleaseVariantValue(&npArgs[i]);

    // Unwrap return values.
    v8::Local<v8::Value> returnValue;
    if (_NPN_IsAlive(npObject))
        returnValue = convertNPVariantToV8Object(isolate, &result, npObject);
    _NPN_ReleaseVariantValue(&result);

    V8SetReturnValue(info, returnValue);
}


void npObjectMethodHandler(const v8::FunctionCallbackInfo<v8::Value>& info)
{
    return npObjectInvokeImpl(info, InvokeMethod);
}


void npObjectInvokeDefaultHandler(const v8::FunctionCallbackInfo<v8::Value>& info)
{
    if (info.IsConstructCall()) {
        npObjectInvokeImpl(info, InvokeConstruct);
        return;
    }

    npObjectInvokeImpl(info, InvokeDefault);
}

class V8TemplateMapTraits : public V8GlobalValueMapTraits<PrivateIdentifier*, v8::FunctionTemplate, v8::kWeakWithParameter> {
public:
    typedef v8::GlobalValueMap<PrivateIdentifier*, v8::FunctionTemplate, V8TemplateMapTraits> MapType;
    typedef PrivateIdentifier WeakCallbackDataType;

    static WeakCallbackDataType* WeakCallbackParameter(MapType* map, PrivateIdentifier* key, const v8::Local<v8::FunctionTemplate>& value)
    {
        return key;
    }

    static void DisposeCallbackData(WeakCallbackDataType* callbackData) { }

    static MapType* MapFromWeakCallbackInfo(
        const v8::WeakCallbackInfo<WeakCallbackDataType>&);

    static PrivateIdentifier* KeyFromWeakCallbackInfo(
        const v8::WeakCallbackInfo<WeakCallbackDataType>& data)
    {
        return data.GetParameter();
    }

    // Dispose traits:
    static void Dispose(v8::Isolate* isolate, v8::Global<v8::FunctionTemplate> value, PrivateIdentifier* key) { }
    static void DisposeWeak(const v8::WeakCallbackInfo<WeakCallbackDataType>& data) { }
    static void OnWeakCallback(const v8::WeakCallbackInfo<WeakCallbackDataType>& data) { }
};


class V8NPTemplateMap {
public:
    // NPIdentifier is PrivateIdentifier*.
    typedef v8::GlobalValueMap<PrivateIdentifier*, v8::FunctionTemplate, V8TemplateMapTraits> MapType;

    v8::Local<v8::FunctionTemplate> get(PrivateIdentifier* key)
    {
        return m_map.Get(key);
    }

    void set(PrivateIdentifier* key, v8::Local<v8::FunctionTemplate> handle)
    {
        DCHECK(!m_map.Contains(key));
        m_map.Set(key, handle);
    }

    static V8NPTemplateMap& sharedInstance(v8::Isolate* isolate)
    {
        DEFINE_STATIC_LOCAL(V8NPTemplateMap, map, (isolate));
        DCHECK(isolate == map.m_map.GetIsolate());
        return map;
    }

    friend class V8TemplateMapTraits;

private:
    explicit V8NPTemplateMap(v8::Isolate* isolate)
        : m_map(isolate)
    {
    }

    MapType m_map;
};

V8TemplateMapTraits::MapType* V8TemplateMapTraits::MapFromWeakCallbackInfo(const v8::WeakCallbackInfo<WeakCallbackDataType>& data)
{
    return &V8NPTemplateMap::sharedInstance(data.GetIsolate()).m_map;
}


static v8::Local<v8::Value> npObjectGetProperty(v8::Isolate* isolate, v8::Local<v8::Object> self, NPIdentifier identifier, v8::Local<v8::Value> key)
{
    NPObject* npObject = v8ObjectToNPObject(self);

    NPUTF8 *str = blink::WebBindings::utf8FromIdentifier(identifier);

    LOG(INFO) << "------ npObjectGetProperty:" << str;

    // Verify that our wrapper wasn't using a NPObject which
    // has already been deleted.
    if (!npObject || !_NPN_IsAlive(npObject)) {
        V8ThrowException::ThrowReferenceError(isolate, "NPObject deleted");
        return v8::Undefined(isolate);
    }

    if (npObject->_class->hasProperty && npObject->_class->getProperty && npObject->_class->hasProperty(npObject, identifier)) {
        if (!_NPN_IsAlive(npObject)) {
            V8ThrowException::ThrowReferenceError(isolate, "NPObject deleted");
            return v8::Undefined(isolate);
        }

        NPVariant result;
        VOID_TO_NPVARIANT(result);
        if (!npObject->_class->getProperty(npObject, identifier, &result)) {
            return v8::Undefined(isolate);
        }

        v8::Local<v8::Value> returnValue;
        if (_NPN_IsAlive(npObject))
            returnValue = convertNPVariantToV8Object(isolate, &result, npObject);
        _NPN_ReleaseVariantValue(&result);
        return returnValue;
    }

    if (!_NPN_IsAlive(npObject)) {
        V8ThrowException::ThrowReferenceError(isolate, "NPObject deleted");
        return v8::Undefined(isolate);
    }

    if (key->IsString() && npObject->_class->hasMethod && npObject->_class->hasMethod(npObject, identifier)) {
        if (!_NPN_IsAlive(npObject)) {
            V8ThrowException::ThrowReferenceError(isolate, "NPObject deleted");
            return v8::Undefined(isolate);
        }

        PrivateIdentifier* id = static_cast<PrivateIdentifier*>(identifier);
        v8::Local<v8::FunctionTemplate> functionTemplate = V8NPTemplateMap::sharedInstance(isolate).get(id);
        // Cache templates using identifier as the key.
        if (functionTemplate.IsEmpty()) {
            // Create a new template.
            functionTemplate = v8::FunctionTemplate::New(isolate);
            functionTemplate->SetCallHandler(npObjectMethodHandler, key);
            V8NPTemplateMap::sharedInstance(isolate).set(id, functionTemplate);
        }
        v8::Local<v8::Function> v8Function;
        if (!functionTemplate->GetFunction(isolate->GetCurrentContext()).ToLocal(&v8Function)) {
            return v8::Local<v8::Value>();
        }
        v8Function->SetName(v8::Local<v8::String>::Cast(key));
        return v8Function;
    }

    return v8::Local<v8::Value>();
}

void npObjectNamedPropertyGetter(v8::Local<v8::String> name, const v8::PropertyCallbackInfo<v8::Value>& info)
{
    LOG(INFO) << "[NPAPI] npObjectNamedPropertyGetter";
    NPIdentifier identifier = getStringIdentifier(info.GetIsolate(), name);
    V8SetReturnValue(info, npObjectGetProperty(info.GetIsolate(), info.Holder(), identifier, name));
}

void npObjectIndexedPropertyGetter(uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info)
{
    NPIdentifier identifier = _NPN_GetIntIdentifier(index);
    V8SetReturnValue(info, npObjectGetProperty(info.GetIsolate(), info.Holder(), identifier, v8::Number::New(info.GetIsolate(), index)));
}

void npObjectGetNamedProperty(v8::Local<v8::Object> self, v8::Local<v8::String> name, const v8::PropertyCallbackInfo<v8::Value>& info)
{
    LOG(INFO) << "[NPAPI] npObjectGetNamedProperty";
    NPIdentifier identifier = getStringIdentifier(info.GetIsolate(), name);
    V8SetReturnValue(info, npObjectGetProperty(info.GetIsolate(), self, identifier, name));
}

void npObjectGetIndexedProperty(v8::Local<v8::Object> self, uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info)
{
    LOG(INFO) << "[NPAPI] npObjectGetIndexedProperty";
    NPIdentifier identifier = _NPN_GetIntIdentifier(index);
    V8SetReturnValue(info, npObjectGetProperty(info.GetIsolate(), self, identifier, v8::Number::New(info.GetIsolate(), index)));
}

void npObjectQueryProperty(v8::Local<v8::String> name, const v8::PropertyCallbackInfo<v8::Integer>& info)
{
    LOG(INFO) << "[NPAPI] npObjectQueryProperty";
    NPIdentifier identifier = getStringIdentifier(info.GetIsolate(), name);
    if (npObjectGetProperty(info.GetIsolate(), info.Holder(), identifier, name).IsEmpty())
        return;
    V8SetReturnValueInt(info, 0);
}

static v8::Local<v8::Value> npObjectSetProperty(v8::Local<v8::Object> self, NPIdentifier identifier, v8::Local<v8::Value> value, v8::Isolate* isolate)
{
    NPObject* npObject = v8ObjectToNPObject(self);

    LOG(INFO) << "[NPAPI] npObjectSetProperty";
    // Verify that our wrapper wasn't using a NPObject which has already been deleted.
    if (!npObject || !_NPN_IsAlive(npObject)) {
        V8ThrowException::ThrowReferenceError(isolate, "NPObject deleted");
        return value; // Intercepted, but an exception was thrown.
    }

    if (npObject->_class->hasProperty && npObject->_class->setProperty && npObject->_class->hasProperty(npObject, identifier)) {
        if (!_NPN_IsAlive(npObject)) {
            V8ThrowException::ThrowReferenceError(isolate, "NPObject deleted");
            return v8::Undefined(isolate);
        }

        NPVariant npValue;
        VOID_TO_NPVARIANT(npValue);
        convertV8ObjectToNPVariant(isolate, value, npObject, &npValue);
        bool success = npObject->_class->setProperty(npObject, identifier, &npValue);
        _NPN_ReleaseVariantValue(&npValue);
        if (success)
            return value; // Intercept the call.
    }
    return v8::Local<v8::Value>();
}


void npObjectNamedPropertySetter(v8::Local<v8::String> name, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<v8::Value>& info)
{
    NPIdentifier identifier = getStringIdentifier(info.GetIsolate(), name);
    V8SetReturnValue(info, npObjectSetProperty(info.Holder(), identifier, value, info.GetIsolate()));
}


void npObjectIndexedPropertySetter(uint32_t index, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<v8::Value>& info)
{
    NPIdentifier identifier = _NPN_GetIntIdentifier(index);
    V8SetReturnValue(info, npObjectSetProperty(info.Holder(), identifier, value, info.GetIsolate()));
}

void npObjectSetNamedProperty(v8::Local<v8::Object> self, v8::Local<v8::String> name, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<v8::Value>& info)
{
    LOG(INFO) << "[NPAPI] npObjectSetNamedProperty";
    NPIdentifier identifier = getStringIdentifier(info.GetIsolate(), name);
    V8SetReturnValue(info, npObjectSetProperty(self, identifier, value, info.GetIsolate()));
}

void npObjectSetIndexedProperty(v8::Local<v8::Object> self, uint32_t index, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<v8::Value>& info)
{
    LOG(INFO) << "[NPAPI] npObjectSetIndexedProperty";
    NPIdentifier identifier = _NPN_GetIntIdentifier(index);
    V8SetReturnValue(info, npObjectSetProperty(self, identifier, value, info.GetIsolate()));
}

void npObjectPropertyEnumerator(const v8::PropertyCallbackInfo<v8::Array>& info, bool namedProperty)
{
    NPObject* npObject = v8ObjectToNPObject(info.Holder());

    LOG(INFO) << "[NPAPI] npObjectPropertyEnumerator";
    // Verify that our wrapper wasn't using a NPObject which
    // has already been deleted.
    if (!npObject || !_NPN_IsAlive(npObject)) {
        V8ThrowException::ThrowReferenceError(info.GetIsolate(), "NPObject deleted");
        return;
    }

    LOG(INFO) << "[NPAPI] npObjectPropertyEnumerator 1";
    if (NP_CLASS_STRUCT_VERSION_HAS_ENUM(npObject->_class) && npObject->_class->enumerate) {
        uint32_t count;
        NPIdentifier* identifiers;
        if (npObject->_class->enumerate(npObject, &identifiers, &count)) {
            uint32_t propertiesCount = 0;
            for (uint32_t i = 0; i < count; ++i) {
                IdentifierRep* identifier = static_cast<IdentifierRep*>(identifiers[i]);
                if (namedProperty == identifier->m_isString)
                    ++propertiesCount;
            }
            v8::Local<v8::Array> properties = v8::Array::New(info.GetIsolate(), propertiesCount);
            for (uint32_t i = 0, propertyIndex = 0; i < count; ++i) {
                IdentifierRep* identifier = static_cast<IdentifierRep*>(identifiers[i]);
                if (namedProperty == identifier->m_isString) {
                    DCHECK(propertyIndex < propertiesCount);
                    v8::Local<v8::Value> value;
                    if (namedProperty)
                        value = V8AtomicString(info.GetIsolate(), identifier->string());
                    else
                        value = v8::Integer::New(info.GetIsolate(), identifier->number());
                    v8::Local<v8::Number> index = v8::Integer::New(info.GetIsolate(), propertyIndex++);
                    if (!(properties->Set(info.GetIsolate()->GetCurrentContext(), index, value)).FromMaybe(false))
                        return;
                }
            }

            V8SetReturnValue(info, properties);
            LOG(INFO) << "[NPAPI] npObjectPropertyEnumerator end";
            return;
        }
    }
}

void npObjectNamedPropertyEnumerator(const v8::PropertyCallbackInfo<v8::Array>& info)
{
    npObjectPropertyEnumerator(info, true);
}

void npObjectIndexedPropertyEnumerator(const v8::PropertyCallbackInfo<v8::Array>& info)
{
    npObjectPropertyEnumerator(info, false);
}

static DOMWrapperMap<NPObject>& staticNPObjectMap()
{
    DEFINE_STATIC_LOCAL(DOMWrapperMap<NPObject>, npObjectMap, (v8::Isolate::GetCurrent()));
    return npObjectMap;
}

template <>
inline void DOMWrapperMap<NPObject>::PersistentValueMapTraits::Dispose(
    v8::Isolate* isolate,
    v8::Global<v8::Object> value,
    NPObject* npObject)
{
    DCHECK(npObject);
    if (_NPN_IsAlive(npObject))
        _NPN_ReleaseObject(npObject);
}

template <>
inline void DOMWrapperMap<NPObject>::PersistentValueMapTraits::DisposeWeak(const v8::WeakCallbackInfo<WeakCallbackDataType>& data)
{
    NPObject* npObject = KeyFromWeakCallbackInfo(data);
    DCHECK(npObject);
    if (_NPN_IsAlive(npObject))
        _NPN_ReleaseObject(npObject);
}

v8::Local<v8::Object> createV8ObjectForNPObject(v8::Isolate* isolate, NPObject* object, NPObject* root)
{
    static v8::Eternal<v8::FunctionTemplate> npObjectDesc;

    DCHECK(isolate->InContext());

    LOG(INFO) << "[NPAPI][TODO]createV8ObjectForNPObject";
    // If this is a v8 object, just return it.
    V8NPObject* v8NPObject = npObjectToV8NPObject(object);
    if (v8NPObject) {
        LOG(INFO) << "[NPAPI][TODO]createV8ObjectForNPObject NEW";
        return v8::Local<v8::Object>::New(isolate, v8NPObject->v8Object);
    }

    // If we've already wrapped this object, just return it.
    //v8::Local<v8::Object> wrapper = staticNPObjectMap().NewLocal(isolate, object);
    v8::Local<v8::Object> wrapper = DOMDataStore::GetWrapper(npObjectToScriptWrappable(object), isolate);
    if (!wrapper.IsEmpty()) {
        LOG(INFO) << "[NPAPI][TODO]createV8ObjectForNPObject wrapper IS NOT EMPTY";
        return wrapper;
    }

    // FIXME: we should create a Wrapper type as a subclass of JSObject. It has two internal fields, field 0 is the wrapped
    // pointer, and field 1 is the type. There should be an api function that returns unused type id. The same Wrapper type
    // can be used by DOM bindings.
    if (npObjectDesc.IsEmpty()) {
        v8::Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
        templ->InstanceTemplate()->SetInternalFieldCount(npObjectInternalFieldCount);
        templ->InstanceTemplate()->SetNamedPropertyHandler(npObjectNamedPropertyGetter, npObjectNamedPropertySetter, npObjectQueryProperty, 0, npObjectNamedPropertyEnumerator);
        templ->InstanceTemplate()->SetIndexedPropertyHandler(npObjectIndexedPropertyGetter, npObjectIndexedPropertySetter, 0, 0, npObjectIndexedPropertyEnumerator);
        templ->InstanceTemplate()->SetCallAsFunctionHandler(npObjectInvokeDefaultHandler);
        npObjectDesc.Set(isolate, templ);
    }

    // FIXME: Move staticNPObjectMap() to DOMDataStore.
    // Use V8DOMWrapper::createWrapper() and
    // V8DOMWrapper::associateObjectWithWrapper()
    // to create a wrapper object.
    v8::Local<v8::Function> v8Function;
    if (!npObjectDesc.Get(isolate)->GetFunction(isolate->GetCurrentContext()).ToLocal(&v8Function)) {
        LOG(ERROR) << "[NPAPI][TODO]createV8ObjectForNPObject 1";
        return v8::Local<v8::Object>();
    }
    v8::Local<v8::Object> value;
    if (!V8ObjectConstructor::NewInstance(isolate, v8Function).ToLocal(&value)) {
        LOG(ERROR) << "[NPAPI][TODO]createV8ObjectForNPObject 2";
        return v8::Local<v8::Object>();
    }

    V8DOMWrapper::SetNativeInfo(isolate, value, npObjectTypeInfo(), npObjectToScriptWrappable(object));

    // KJS retains the object as part of its wrapper (see Bindings::CInstance).
    _NPN_RetainObject(object);
    _NPN_RegisterObject(object, root);

    //staticNPObjectMap().Set(object, npObjectTypeInfo(), value);
    DOMDataStore::SetWrapper(isolate, npObjectToScriptWrappable(object), npObjectTypeInfo(), value);
    DCHECK(V8DOMWrapper::HasInternalFieldsSet(value));
    LOG(INFO) << "[NPAPI][TODO]createV8ObjectForNPObject END";
    return value;
}

void forgetV8ObjectForNPObject(NPObject* object)
{
    LOG(INFO) << "[NPAPI] forgetV8ObjectForNPObject";
#ifdef USE_UNIONTECH_NPAPI_TODO
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Object> wrapper = staticNPObjectMap().NewLocal(isolate, object);
    if (!wrapper.IsEmpty()) {
        V8DOMWrapper::ClearNativeInfo(wrapper, npObjectTypeInfo());
        staticNPObjectMap().RemoveAndDispose(object);
        _NPN_ReleaseObject(object);
    }
#endif
}

} // namespace blink
