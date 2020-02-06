using System;

namespace DeftlrLibraries
{
    static class ProjectExtensions
    {
        public static T Print<T>(this T o, params string[] parameters)
        {
            Console.WriteLine(o.ConvertToJson().Format(parameters));
            return o;
        }

        public static string Format(this string text, params string[] parameters)
        {
            return (parameters.Length > 0) ? String.Format(text, parameters) : text;
        }
    }
}
