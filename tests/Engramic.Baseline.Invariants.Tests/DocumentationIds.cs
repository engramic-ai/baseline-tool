using System.Reflection;

namespace Engramic.Baseline.Invariants.Tests;

/// <summary>
/// Documentation comment IDs (the format of BannedSymbols.txt) for members found by reflection, such as
/// M:System.Text.Json.JsonSerializer.Serialize``1(``0,System.Text.Json.JsonSerializerOptions).
/// </summary>
internal static class DocumentationIds
{
    public static string Of(MemberInfo member)
    {
        return member switch
        {
            Type type => "T:" + TypeName(type),
            ConstructorInfo constructor => "M:" + TypeName(constructor.DeclaringType!) + (constructor.IsStatic ? ".#cctor" : ".#ctor") + Parameters(constructor.GetParameters()),
            MethodInfo method => "M:" + TypeName(method.DeclaringType!) + "." + method.Name
                + (method.IsGenericMethodDefinition ? "``" + method.GetGenericArguments().Length : string.Empty)
                + Parameters(method.GetParameters())
                + (method.Name is "op_Implicit" or "op_Explicit" ? "~" + ParameterType(method.ReturnType) : string.Empty),
            PropertyInfo property => "P:" + TypeName(property.DeclaringType!) + "." + property.Name + Parameters(property.GetIndexParameters()),
            FieldInfo field => "F:" + TypeName(field.DeclaringType!) + "." + field.Name,
            EventInfo @event => "E:" + TypeName(@event.DeclaringType!) + "." + @event.Name,
            _ => throw new ArgumentException("No documentation ID for " + member.MemberType, nameof(member)),
        };
    }

    /// <summary>The IDs of a type and all its public members, declared on it or inherited.</summary>
    public static IEnumerable<string> OfTypeAndMembers(Type type)
    {
        yield return Of(type);
        const BindingFlags all = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static;
        foreach (var member in type.GetMembers(all))
        {
            if (member is Type)
            {
                continue;
            }

            yield return Of(member);
        }
    }

    private static string Parameters(ParameterInfo[] parameters)
    {
        return parameters.Length == 0 ? string.Empty : "(" + string.Join(",", parameters.Select(p => ParameterType(p.ParameterType))) + ")";
    }

    private static string ParameterType(Type type)
    {
        if (type.IsByRef)
        {
            return ParameterType(type.GetElementType()!) + "@";
        }

        if (type.IsPointer)
        {
            return ParameterType(type.GetElementType()!) + "*";
        }

        if (type.IsArray)
        {
            var rank = type.GetArrayRank();
            return ParameterType(type.GetElementType()!) + (rank == 1 ? "[]" : "[" + string.Join(",", Enumerable.Repeat("0:", rank)) + "]");
        }

        if (type.IsGenericMethodParameter)
        {
            return "``" + type.GenericParameterPosition;
        }

        if (type.IsGenericTypeParameter)
        {
            return "`" + type.GenericParameterPosition;
        }

        if (type.IsGenericType)
        {
            var name = TypeName(type.GetGenericTypeDefinition());
            return name[..name.LastIndexOf('`')] + "{" + string.Join(",", type.GetGenericArguments().Select(ParameterType)) + "}";
        }

        return TypeName(type);
    }

    private static string TypeName(Type type)
    {
        if (type.IsNested)
        {
            return TypeName(type.DeclaringType!) + "." + type.Name;
        }

        return type.Namespace is null ? type.Name : type.Namespace + "." + type.Name;
    }
}
