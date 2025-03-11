using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace SigningServer.ClientCore.Configuration;

// https://github.com/dotnet/runtime/issues/84018
// https://github.com/dotnet/runtime/issues/29538#issuecomment-1330494636

internal class JsonPopulate
{
    // Dynamically attach a JsonSerializerOptions copy that is configured using PopulateTypeInfoResolver
    private static readonly ConditionalWeakTable<JsonSerializerOptions, JsonSerializerOptions> PopulateMap = new();

    public static void PopulateObject(string json, Type returnType, object destination, JsonSerializerOptions options)
    {
        options = GetOptionsWithPopulateResolver(options);
        PopulateTypeInfoResolver.RootObjectToPopulate = destination;
        try
        {
            var result = JsonSerializer.Deserialize(json, returnType, options);
            Debug.Assert(ReferenceEquals(result, destination));
        }
        finally
        {
            PopulateTypeInfoResolver.RootObjectToPopulate = null;
        }
    }

    private static JsonSerializerOptions GetOptionsWithPopulateResolver(JsonSerializerOptions options)
    {
        if (!PopulateMap.TryGetValue(options, out var populateResolverOptions))
        {
            JsonSerializer.Serialize(value: 0, options); // Force a serialization to mark options as read-only
            Debug.Assert(options.TypeInfoResolver != null);

            populateResolverOptions = new JsonSerializerOptions(options)
            {
                TypeInfoResolver = new PopulateTypeInfoResolver(options.TypeInfoResolver)
            };

            PopulateMap.TryAdd(options, populateResolverOptions);
        }

        Debug.Assert(populateResolverOptions.TypeInfoResolver is PopulateTypeInfoResolver);
        return populateResolverOptions;
    }

    private class PopulateTypeInfoResolver(IJsonTypeInfoResolver jsonTypeInfoResolver) : IJsonTypeInfoResolver
    {
        [ThreadStatic]
        internal static object? RootObjectToPopulate;

        public JsonTypeInfo? GetTypeInfo(Type type, JsonSerializerOptions options)
        {
            var typeInfo = jsonTypeInfoResolver.GetTypeInfo(type, options);
            if (typeInfo != null && typeInfo.Kind != JsonTypeInfoKind.None)
            {
                var defaultCreateObjectDelegate = typeInfo.CreateObject;
                typeInfo.CreateObject = () =>
                {
                    var result = RootObjectToPopulate;
                    if (result != null)
                    {
                        // clean up to prevent reuse in recursive scenaria
                        RootObjectToPopulate = null;
                    }
                    else
                    {
                        // fall back to the default delegate
                        result = defaultCreateObjectDelegate?.Invoke();
                    }

                    return result!;
                };
            }

            return typeInfo;
        }
    }
}

