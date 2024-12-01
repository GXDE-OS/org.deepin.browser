/*
 * Copyright (C) 2004, 2006 Apple Computer, Inc.  All rights reserved.
 * Copyright (C) 2007, 2008, 2009 Google, Inc.  All rights reserved.
 * Copyright (C) 2014 Opera Software ASA. All rights reserved.
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

#include <stdio.h>
#include <stddef.h>

#include "base/memory/ptr_util.h"
#include "third_party/blink/renderer/bindings/core/v8/V8NPUtils.h"
#include "third_party/blink/renderer/bindings/core/v8/npruntime_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/npruntime_priv.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_source_code.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_script_runner.h"
#include "third_party/blink/renderer/core/dom/document.h"
//#include "third_party/blink/renderer/core/dom/user_gesture_indicator.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/bindings/v8_object_constructor.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_context_data.h"
#include "third_party/blink/renderer/platform/bindings/wrapper_type_info.h"
//#include "third_party/blink/renderer/platform/wtf/string_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wheader-hygiene"
using namespace blink;
#pragma clang diagnostic pop

namespace blink {

const WrapperTypeInfo* npObjectTypeInfo()
{
    static const WrapperTypeInfo typeInfo = {
        gin::kEmbedderBlink,
        nullptr,
        nullptr,
        "NPObject",
        nullptr,
        WrapperTypeInfo::kWrapperTypeObjectPrototype,
        WrapperTypeInfo::kObjectClassId,
        WrapperTypeInfo::kNotInheritFromActiveScriptWrappable,
		WrapperTypeInfo::RefCountedObject
    };
    return &typeInfo;
}

// FIXME: Comments on why use malloc and free.
static NPObject* allocV8NPObject(NPP, NPClass*)
{
    return static_cast<NPObject*>(malloc(sizeof(V8NPObject)));
}

static void freeV8NPObject(NPObject* npObject)
{
    V8NPObject* v8NpObject = reinterpret_cast<V8NPObject*>(npObject);
    disposeUnderlyingV8Object(v8::Isolate::GetCurrent(), npObject);
    free(v8NpObject);
}

static NPClass V8NPObjectClass = {
    NP_CLASS_STRUCT_VERSION,
    allocV8NPObject,
    freeV8NPObject,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static ScriptState* mainWorldScriptState(v8::Isolate* isolate, NPObject* npObject)
{
    DCHECK(npObject->_class == &V8NPObjectClass);
    V8NPObject* object = reinterpret_cast<V8NPObject*>(npObject);
    LocalDOMWindow* window = object->rootObject;
    if (!window || !window->GetFrame())
        return nullptr;
    return ToScriptStateForMainWorld(window->GetFrame());
}

static std::unique_ptr<v8::Local<v8::Value>[]> createValueListFromVariantArgs(v8::Isolate* isolate,
                                                                              const NPVariant* arguments,
                                                                              uint32_t argumentCount,
                                                                              NPObject* owner)
{
    std::unique_ptr<v8::Local<v8::Value>[]> argv = std::make_unique<v8::Local<v8::Value>[]>(argumentCount);
    for (uint32_t index = 0; index < argumentCount; index++) {
        const NPVariant* arg = &arguments[index];
        argv[index] = convertNPVariantToV8Object(isolate, arg, owner);
    }
    return argv;
}

// Create an identifier (null terminated utf8 char*) from the NPIdentifier.
static v8::Local<v8::String> npIdentifierToV8Identifier(v8::Isolate* isolate, NPIdentifier name)
{
    PrivateIdentifier* identifier = static_cast<PrivateIdentifier*>(name);
    if (identifier->isString)
        return V8AtomicString(isolate, static_cast<const char*>(identifier->value.string));

    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%d", identifier->value.number);
    return V8AtomicString(isolate, buffer);
}

NPObject* v8ObjectToNPObject(v8::Local<v8::Object> object) {
  NPObjectWrapperBase* wrappable = static_cast<NPObjectWrapperBase*>(ToScriptWrappable(object));
  return npObjectWrapperBaseToNPObject(wrappable);
}

bool isWrappedNPObject(v8::Local<v8::Object> object)
{
    return object->InternalFieldCount() == npObjectInternalFieldCount
        && ToWrapperTypeInfo(object) == npObjectTypeInfo();
}

NPObject* npCreateV8ScriptObject(v8::Isolate* isolate, NPP npp, v8::Local<v8::Object> object, LocalDOMWindow* root)
{
    DLOG(INFO) << "[NPAPI][BLINK]  npCreateV8ScriptObject";
    // Check to see if this object is already wrapped.
    if (isWrappedNPObject(object)) {
        NPObject* returnValue = v8ObjectToNPObject(object);
        _NPN_RetainObject(returnValue);
        return returnValue;
    }

    V8NPObjectVector* objectVector = 0;
    if (!object->CreationContext().IsEmpty()){
        if (V8PerContextData* perContextData = V8PerContextData::From(object->CreationContext())) {
            int v8ObjectHash = object->GetIdentityHash();
            DCHECK(v8ObjectHash);
            V8NPObjectMap* v8NPObjectMap = perContextData->v8NPObjectMap();
            V8NPObjectMap::iterator iter = v8NPObjectMap->find(v8ObjectHash);
            if (iter != v8NPObjectMap->end()) {
                V8NPObjectVector& objects = iter->value;
                for (size_t index = 0; index < objects.size(); ++index) {
                    V8NPObject* v8npObject = objects.at(index);
                    if (v8npObject->v8Object == object && v8npObject->rootObject == root) {
                        _NPN_RetainObject(&v8npObject->object);
                        return reinterpret_cast<NPObject*>(v8npObject);
                    }
                }
                objectVector = &iter->value;
            } else {
                objectVector = &v8NPObjectMap->Set(v8ObjectHash, V8NPObjectVector()).stored_value->value;
            }
        }
    }

    V8NPObject* v8npObject = reinterpret_cast<V8NPObject*>(_NPN_CreateObject(npp, &V8NPObjectClass));
    // This is uninitialized memory, we need to clear it so that
    // Persistent::Reset won't try to Dispose anything bogus.
    new (&v8npObject->v8Object) v8::Persistent<v8::Object>();
    v8npObject->v8Object.Reset(isolate, object);
    v8npObject->rootObject = root;

    if (objectVector)
      objectVector->Append(v8npObject);

    return reinterpret_cast<NPObject*>(v8npObject);
}

V8NPObject* npObjectToV8NPObject(NPObject* npObject)
{
    if (npObject->_class != &V8NPObjectClass)
        return 0;
    V8NPObject* v8NpObject = reinterpret_cast<V8NPObject*>(npObject);
    if (v8NpObject->v8Object.IsEmpty())
        return 0;
    return v8NpObject;
}

NPObject* npObjectWrapperBaseToNPObject(NPObjectWrapperBase* wrapperBase) {
  DCHECK(wrapperBase != nullptr);

  return static_cast<NPObject*>(wrapperBase->object.Get());
}

NPObjectWrapperBase* npObjectToNPObjectWrapperBase(NPObject* npObject) {
  DCHECK(npObject != nullptr);

  NPObjectEx* obj = static_cast<NPObjectEx*>(npObject);

  return obj->wrapper_.Get();
}

ScriptWrappable* npObjectToScriptWrappable(NPObject* npObject)
{
  NPObjectWrapperBase* wraper = npObjectToNPObjectWrapperBase(npObject);

  return static_cast<ScriptWrappable*>(wraper);
}

void disposeUnderlyingV8Object(v8::Isolate* isolate, NPObject* npObject)
{
    LOG(INFO) << "[NPAPI][BLINK]  disposeUnderlyingV8Object";
    DCHECK(npObject);
    V8NPObject* v8NpObject = npObjectToV8NPObject(npObject);
    if (!v8NpObject)
        return;
    v8::HandleScope scope(isolate);
    v8::Local<v8::Object> v8Object = v8::Local<v8::Object>::New(isolate, v8NpObject->v8Object);
    if (!v8Object->CreationContext().IsEmpty()) {
        if (V8PerContextData* perContextData = V8PerContextData::From(v8Object->CreationContext())) {
            V8NPObjectMap* v8NPObjectMap = perContextData->v8NPObjectMap();
            int v8ObjectHash = v8Object->GetIdentityHash();
            DCHECK(v8ObjectHash);
            V8NPObjectMap::iterator iter = v8NPObjectMap->find(v8ObjectHash);
            if (iter != v8NPObjectMap->end()) {
                V8NPObjectVector& objects = iter->value;
                for (size_t index = 0; index < objects.size(); ++index) {
                    if (objects.at(index) == v8NpObject) {
                        objects.EraseAt(index);
                        break;
                    }
                }
                if (objects.IsEmpty())
                    v8NPObjectMap->erase(v8ObjectHash);
            }
        }
    }
    v8NpObject->v8Object.Reset();
    v8NpObject->rootObject = 0;
}

} // namespace blink

bool _NPN_Invoke(NPP npp, NPObject* npObject, NPIdentifier methodName, const NPVariant* arguments, uint32_t argumentCount, NPVariant* result)
{
    LOG(INFO) << "[NPAPI][BLINK]  _NPN_Invoke";
    if (!npObject)
        return false;

    v8::Isolate* isolate = v8::Isolate::GetCurrent();

    V8NPObject* v8NpObject = npObjectToV8NPObject(npObject);
    if (!v8NpObject) {
        if (npObject->_class->invoke)
            return npObject->_class->invoke(npObject, methodName, arguments, argumentCount, result);

        VOID_TO_NPVARIANT(*result);
        return true;
    }

    PrivateIdentifier* identifier = static_cast<PrivateIdentifier*>(methodName);
    if (!identifier->isString)
        return false;

    if (!strcmp(identifier->value.string, "eval")) {
        if (argumentCount != 1)
            return false;
        if (arguments[0].type != NPVariantType_String)
            return false;
        return _NPN_Evaluate(npp, npObject, const_cast<NPString*>(&arguments[0].value.stringValue), result);
    }

    // FIXME: should use the plugin's owner frame as the security context.
    ScriptState* scriptState = mainWorldScriptState(isolate, npObject);
    if (!scriptState)
        return false;

  ScriptState::Scope scope(scriptState);
  v8::TryCatch tryCatch(isolate);

    v8::Local<v8::Object> v8Object = v8::Local<v8::Object>::New(isolate, v8NpObject->v8Object);
    v8::Local<v8::Value> functionObject;
    if (!v8Object->Get(scriptState->GetContext(), V8AtomicString(scriptState->GetIsolate(), identifier->value.string)).ToLocal(&functionObject) || functionObject->IsNull()) {
        NULL_TO_NPVARIANT(*result);
        return false;
    }
    if (functionObject->IsUndefined()) {
        VOID_TO_NPVARIANT(*result);
        return false;
    }

    LocalFrame* frame = v8NpObject->rootObject->GetFrame();
    DCHECK(frame);

    // Call the function object.
    v8::Local<v8::Function> function = v8::Local<v8::Function>::Cast(functionObject);
    std::unique_ptr<v8::Local<v8::Value>[]> argv = createValueListFromVariantArgs(isolate, arguments, argumentCount, npObject);
    // If we had an error, return false.  The spec is a little unclear here, but says "Returns true if the method was
    // successfully invoked".  If we get an error return value, was that successfully invoked?
    v8::Local<v8::Value> resultObject;
    if (!V8ScriptRunner::CallFunction(function, frame->GetDocument()->ToExecutionContext(), v8Object,
                                      argumentCount, argv.get(),
                                      frame->GetScriptController().GetIsolate()).ToLocal(&resultObject)) {
        return false;
    }

    convertV8ObjectToNPVariant(isolate, resultObject, npObject, result);
    return true;
}

// FIXME: Fix it same as _NPN_Invoke (HandleScope and such).
bool _NPN_InvokeDefault(NPP npp, NPObject* npObject, const NPVariant* arguments, uint32_t argumentCount, NPVariant* result)
{
    LOG(INFO) << "[NPAPI][BLINK]  _NPN_InvokeDefault";
    if (!npObject)
        return false;

    v8::Isolate* isolate = v8::Isolate::GetCurrent();

    V8NPObject* v8NpObject = npObjectToV8NPObject(npObject);
    if (!v8NpObject) {
        if (npObject->_class->invokeDefault)
            return npObject->_class->invokeDefault(npObject, arguments, argumentCount, result);

        VOID_TO_NPVARIANT(*result);
        return true;
    }

    VOID_TO_NPVARIANT(*result);

    ScriptState* scriptState = mainWorldScriptState(isolate, npObject);
    if (!scriptState)
        return false;

  ScriptState::Scope scope(scriptState);
  v8::TryCatch tryCatch(isolate);

    // Lookup the function object and call it.
    v8::Local<v8::Object> functionObject = v8::Local<v8::Object>::New(isolate, v8NpObject->v8Object);
    if (!functionObject->IsFunction())
        return false;

    v8::Local<v8::Function> function = v8::Local<v8::Function>::Cast(functionObject);
    if (function->IsNull())
        return false;

    LocalFrame* frame = v8NpObject->rootObject->GetFrame();
    DCHECK(frame);

    std::unique_ptr<v8::Local<v8::Value>[]> argv = createValueListFromVariantArgs(isolate, arguments, argumentCount, npObject);
    // If we had an error, return false.  The spec is a little unclear here, but says "Returns true if the method was
    // successfully invoked".  If we get an error return value, was that successfully invoked?
    v8::Local<v8::Value> resultObject;
    if (!V8ScriptRunner::CallFunction(function, frame->GetDocument()->ToExecutionContext(),
                                      functionObject, argumentCount, argv.get(),
                                      frame->GetScriptController().GetIsolate()).ToLocal(&resultObject)) {
        return false;
    }

    convertV8ObjectToNPVariant(isolate, resultObject, npObject, result);
    return true;
}

bool _NPN_Evaluate(NPP npp, NPObject* npObject, NPString* npScript, NPVariant* result)
{
    // FIXME: Give the embedder a way to control this.
    bool popupsAllowed = false;
    return _NPN_EvaluateHelper(npp, popupsAllowed, npObject, npScript, result);
}

bool _NPN_EvaluateHelper(NPP npp, bool popupsAllowed, NPObject* npObject, NPString* npScript, NPVariant* result)
{
    VOID_TO_NPVARIANT(*result);
    if (ScriptForbiddenScope::IsScriptForbidden())
        return false;

    if (!npObject)
        return false;

    V8NPObject* v8NpObject = npObjectToV8NPObject(npObject);
    if (!v8NpObject)
        return false;

    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    ScriptState* scriptState = mainWorldScriptState(isolate, npObject);
    if (!scriptState)
        return false;

    ScriptState::Scope scope(scriptState);
    v8::TryCatch tryCatch(isolate);

    // FIXME: Is this branch still needed after switching to using UserGestureIndicator?
    String filename;
    if (!popupsAllowed)
        filename = "npscript";

    LocalFrame* frame = v8NpObject->rootObject->GetFrame();
    DCHECK(frame);

    String script = String::FromUTF8(npScript->UTF8Characters, npScript->UTF8Length);

    DLOG(INFO) << "[NPAPI][BLINK] ExecuteScriptAndReturnValue";
    //UserGestureIndicator gestureIndicator(popupsAllowed ? UserGestureToken::kNewGesture
    //                                      : UserGestureToken::kPossiblyExistingGesture);
    v8::Local<v8::Value> v8result = frame->GetScriptController().ExecuteScriptAndReturnValue(
                                    scriptState->GetContext(),
                                    ScriptSourceCode(script, ScriptSourceLocationType::kUnknown, nullptr, KURL(filename)),
                                    KURL(), 
                                    SanitizeScriptErrors::kDoNotSanitize);

    if (v8result.IsEmpty())
        return false;

    if (_NPN_IsAlive(npObject))
        convertV8ObjectToNPVariant(isolate, v8result, npObject, result);
    return true;
}

bool _NPN_GetProperty(NPP npp, NPObject* npObject, NPIdentifier propertyName, NPVariant* result)
{
    DLOG(INFO) << "[NPAPI][BLINK]  _NPN_GetProperty";
    if (!npObject)
        return false;

    if (V8NPObject* object = npObjectToV8NPObject(npObject)) {
        v8::Isolate* isolate = v8::Isolate::GetCurrent();
        ScriptState* scriptState = mainWorldScriptState(isolate, npObject);
        if (!scriptState)
            return false;

        ScriptState::Scope scope(scriptState);
        v8::TryCatch tryCatch(isolate);

        v8::Local<v8::Object> obj = v8::Local<v8::Object>::New(isolate, object->v8Object);
        v8::Local<v8::Value> v8result;
        if (!obj->Get(scriptState->GetContext(), npIdentifierToV8Identifier(scriptState->GetIsolate(), propertyName)).ToLocal(&v8result))
            return false;

        convertV8ObjectToNPVariant(isolate, v8result, npObject, result);
        return true;
    }

    if (npObject->_class->hasProperty && npObject->_class->getProperty) {
        if (npObject->_class->hasProperty(npObject, propertyName))
            return npObject->_class->getProperty(npObject, propertyName, result);
    }

    VOID_TO_NPVARIANT(*result);
    return false;
}

bool _NPN_SetProperty(NPP npp, NPObject* npObject, NPIdentifier propertyName, const NPVariant* value)
{
    LOG(INFO) << "[NPAPI][BLINK]  _NPN_SetProperty";
    if (!npObject)
        return false;

    if (V8NPObject* object = npObjectToV8NPObject(npObject)) {
        v8::Isolate* isolate = v8::Isolate::GetCurrent();
        ScriptState* scriptState = mainWorldScriptState(isolate, npObject);
        if (!scriptState)
            return false;

    ScriptState::Scope scope(scriptState);
    v8::TryCatch tryCatch(isolate);

        v8::Local<v8::Object> obj = v8::Local<v8::Object>::New(isolate, object->v8Object);
        return (obj->Set(scriptState->GetContext(), npIdentifierToV8Identifier(isolate, propertyName), convertNPVariantToV8Object(isolate, value, object->rootObject->GetFrame()->GetScriptController().WindowScriptNPObject()))).FromMaybe(false);
    }

    if (npObject->_class->setProperty)
        return npObject->_class->setProperty(npObject, propertyName, value);

    return false;
}

bool _NPN_RemoveProperty(NPP npp, NPObject* npObject, NPIdentifier propertyName)
{
    LOG(INFO) << "[NPAPI][BLINK]  _NPN_RemoveProperty";
    if (!npObject)
        return false;

    V8NPObject* object = npObjectToV8NPObject(npObject);
    if (!object)
        return false;

    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    ScriptState* scriptState = mainWorldScriptState(isolate, npObject);
    if (!scriptState)
        return false;
    ScriptState::Scope scope(scriptState);
    v8::TryCatch tryCatch(isolate);

    v8::Local<v8::Object> obj = v8::Local<v8::Object>::New(isolate, object->v8Object);
    // FIXME: Verify that setting to undefined is right.
    return (obj->Set(scriptState->GetContext(), npIdentifierToV8Identifier(isolate, propertyName), v8::Undefined(isolate))).FromMaybe(false);
}

bool _NPN_HasProperty(NPP npp, NPObject* npObject, NPIdentifier propertyName)
{
    LOG(INFO) << "[NPAPI][BLINK]  _NPN_HasProperty 1";
    if (!npObject)
        return false;

    if (V8NPObject* object = npObjectToV8NPObject(npObject)) {
        v8::Isolate* isolate = v8::Isolate::GetCurrent();
        ScriptState* scriptState = mainWorldScriptState(isolate, npObject);
        if (!scriptState)
            return false;
        ScriptState::Scope scope(scriptState);
        v8::TryCatch tryCatch(isolate);

        v8::Local<v8::Object> obj = v8::Local<v8::Object>::New(scriptState->GetIsolate(), object->v8Object);
	    LOG(INFO) << "[NPAPI][BLINK]  _NPN_HasProperty 2";
        return (obj->Has(scriptState->GetContext(), npIdentifierToV8Identifier(scriptState->GetIsolate(), propertyName))).FromMaybe(false);
    }

    if (npObject->_class->hasProperty)
        return npObject->_class->hasProperty(npObject, propertyName);
    return false;
}

bool _NPN_HasMethod(NPP npp, NPObject* npObject, NPIdentifier methodName)
{
    LOG(INFO) << "[NPAPI][BLINK]  _NPN_HasMethod";
    if (!npObject)
        return false;

    if (V8NPObject* object = npObjectToV8NPObject(npObject)) {
        v8::Isolate* isolate = v8::Isolate::GetCurrent();
        ScriptState* scriptState = mainWorldScriptState(isolate, npObject);
        if (!scriptState)
            return false;
        ScriptState::Scope scope(scriptState);
        v8::TryCatch tryCatch(isolate);

        v8::Local<v8::Object> obj = v8::Local<v8::Object>::New(isolate, object->v8Object);
        v8::Local<v8::Value> prop;
        if (!obj->Get(scriptState->GetContext(), npIdentifierToV8Identifier(scriptState->GetIsolate(), methodName)).ToLocal(&prop))
            return false;
        return prop->IsFunction();
    }

    if (npObject->_class->hasMethod)
        return npObject->_class->hasMethod(npObject, methodName);
    return false;
}

void _NPN_SetException(NPObject* npObject, const NPUTF8 *message)
{
    LOG(INFO) << "[NPAPI][BLINK]  _NPN_SetException";
    if (!npObject || !npObjectToV8NPObject(npObject)) {
        // We won't be able to find a proper scope for this exception, so just throw it.
        // This is consistent with JSC, which throws a global exception all the time.
        V8ThrowException::ThrowError(v8::Isolate::GetCurrent(), message);
        return;
    }

    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    ScriptState* scriptState = mainWorldScriptState(isolate, npObject);
    if (!scriptState)
        return;

    ScriptState::Scope scope(scriptState);
    v8::TryCatch tryCatch(isolate);

    V8ThrowException::ThrowError(isolate, message);
}

bool _NPN_Enumerate(NPP npp, NPObject* npObject, NPIdentifier** identifier, uint32_t* count)
{
    LOG(INFO) << "[NPAPI][BLINK]  _NPN_Enumerate";
    if (!npObject)
        return false;

    if (V8NPObject* object = npObjectToV8NPObject(npObject)) {
        ScriptState* scriptState = mainWorldScriptState(v8::Isolate::GetCurrent(), npObject);
        if (!scriptState)
            return false;
        ScriptState::Scope scope(scriptState);
        v8::TryCatch tryCatch(scriptState->GetIsolate());

        v8::Local<v8::Object> obj = v8::Local<v8::Object>::New(scriptState->GetIsolate(), object->v8Object);

        // FIXME: http://b/issue?id=1210340: Use a v8::Object::Keys() method when it exists, instead of evaluating javascript.

        // FIXME: Figure out how to cache this helper function.  Run a helper function that collects the properties
        // on the object into an array.
        const char enumeratorCode[] =
            "(function (obj) {"
            "  var props = [];"
            "  for (var prop in obj) {"
            "    props[props.length] = prop;"
            "  }"
            "  return props;"
            "});";
        ScriptSourceCode source(enumeratorCode);
        v8::Local<v8::Value> result;
        if (!V8ScriptRunner::CompileAndRunInternalScript(scriptState->GetIsolate(), scriptState, source).ToLocal(&result))
            return false;
        DCHECK(result->IsFunction());
        v8::Local<v8::Function> enumerator = v8::Local<v8::Function>::Cast(result);
        v8::Local<v8::Value> argv[] = { obj };
        v8::Local<v8::Value> propsObj;
        if (!V8ScriptRunner::CallInternalFunction(
             scriptState->GetIsolate(), nullptr,
             enumerator, v8::Local<v8::Object>::Cast(result), base::size(argv), argv)
             .ToLocal(&propsObj))
            return false;

        // Convert the results into an array of NPIdentifiers.
        v8::Local<v8::Array> props = v8::Local<v8::Array>::Cast(propsObj);
        *count = props->Length();
        *identifier = static_cast<NPIdentifier*>(calloc(*count, sizeof(NPIdentifier)));
        for (uint32_t i = 0; i < *count; ++i) {
            v8::Local<v8::Value> name;
            if (!props->Get(scriptState->GetContext(), v8::Integer::New(scriptState->GetIsolate(), i)).ToLocal(&name))
                return false;
            (*identifier)[i] = getStringIdentifier(scriptState->GetIsolate(), v8::Local<v8::String>::Cast(name));
        }
        return true;
    }

    if (NP_CLASS_STRUCT_VERSION_HAS_ENUM(npObject->_class) && npObject->_class->enumerate)
       return npObject->_class->enumerate(npObject, identifier, count);

    return false;
}

bool _NPN_Construct(NPP npp, NPObject* npObject, const NPVariant* arguments, uint32_t argumentCount, NPVariant* result)
{
    LOG(INFO) << "[NPAPI][BLINK]  _NPN_Construct";
    if (!npObject)
        return false;

    if (V8NPObject* object = npObjectToV8NPObject(npObject)) {
        ScriptState* scriptState = mainWorldScriptState(v8::Isolate::GetCurrent(), npObject);
        if (!scriptState)
            return false;
        ScriptState::Scope scope(scriptState);
        v8::TryCatch tryCatch(scriptState->GetIsolate());

        // Lookup the constructor function.
        v8::Local<v8::Object> ctorObj = v8::Local<v8::Object>::New(scriptState->GetIsolate(), object->v8Object);
        if (!ctorObj->IsFunction())
            return false;

        // Call the constructor.
        v8::Local<v8::Value> resultObject;
        v8::Local<v8::Function> ctor = v8::Local<v8::Function>::Cast(ctorObj);
        if (ctor->IsNull())
            return false;

        LocalFrame* frame = object->rootObject->GetFrame();
        DCHECK(frame);
        std::unique_ptr<v8::Local<v8::Value>[]> argv =
            createValueListFromVariantArgs(scriptState->GetIsolate(), arguments, argumentCount, npObject);
        if (!V8ObjectConstructor::NewInstanceInDocument(
             scriptState->GetIsolate(), ctor, argumentCount, argv.get(),
             frame ? frame->GetDocument() : 0)
             .ToLocal(&resultObject)) {
            return false;
        }

        convertV8ObjectToNPVariant(scriptState->GetIsolate(), resultObject, npObject, result);
        return true;
    }

    if (NP_CLASS_STRUCT_VERSION_HAS_CTOR(npObject->_class) && npObject->_class->construct)
        return npObject->_class->construct(npObject, arguments, argumentCount, result);

    return false;
}
