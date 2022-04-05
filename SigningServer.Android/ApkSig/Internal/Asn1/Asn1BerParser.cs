/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Text;
using SigningServer.Android;
using SigningServer.Android.ApkSig.Internal.Asn1;
using SigningServer.Android.ApkSig.Internal.Asn1.Ber;
using SigningServer.Android.ApkSig.Internal.Util;

namespace SigningServer.Android.ApkSig.Internal.Asn1
{
    /**
     * Parser of ASN.1 BER-encoded structures.
     *
     * <p>Structure is described to the parser by providing a class annotated with {@link Asn1Class},
     * containing fields annotated with {@link Asn1Field}.
     */
    public static class Asn1BerParser
    {
        /**
         * Returns the ASN.1 structure contained in the BER encoded input.
         *
         * @param encoded encoded input. If the decoding operation succeeds, the position of this buffer
         *        is advanced to the first position following the end of the consumed structure.
         * @param containerClass class describing the structure of the input. The class must meet the
         *        following requirements:
         *        <ul>
         *        <li>The class must be annotated with {@link Asn1Class}.</li>
         *        <li>The class must expose a public no-arg constructor.</li>
         *        <li>Member fields of the class which are populated with parsed input must be
         *            annotated with {@link Asn1Field} and be public and non-final.</li>
         *        </ul>
         *
         * @throws Asn1DecodingException if the input could not be decoded into the specified Java
         *         object
         */
        public static T parse<T>(ByteBuffer encoded)
        {
            BerDataValue containerDataValue;
            try
            {
                containerDataValue = new ByteBufferBerDataValueReader(encoded).readDataValue();
            }
            catch (BerDataValueFormatException e)
            {
                throw new Asn1DecodingException("Failed to decode top-level data value", e);
            }

            if (containerDataValue == null)
            {
                throw new Asn1DecodingException("Empty input");
            }

            return parse<T>(containerDataValue);
        }

        /**
         * Returns the implicit {@code SET OF} contained in the provided ASN.1 BER input. Implicit means
         * that this method does not care whether the tag number of this data structure is
         * {@code SET OF} and whether the tag class is {@code UNIVERSAL}.
         *
         * <p>Note: The returned type is {@link List} rather than {@link java.util.Set} because ASN.1
         * SET may contain duplicate elements.
         *
         * @param encoded encoded input. If the decoding operation succeeds, the position of this buffer
         *        is advanced to the first position following the end of the consumed structure.
         * @param elementClass class describing the structure of the values/elements contained in this
         *        container. The class must meet the following requirements:
         *        <ul>
         *        <li>The class must be annotated with {@link Asn1Class}.</li>
         *        <li>The class must expose a public no-arg constructor.</li>
         *        <li>Member fields of the class which are populated with parsed input must be
         *            annotated with {@link Asn1Field} and be public and non-final.</li>
         *        </ul>
         *
         * @throws Asn1DecodingException if the input could not be decoded into the specified Java
         *         object
         */
        public static List<T> parseImplicitSetOf<T>(ByteBuffer encoded)
        {
            BerDataValue containerDataValue;
            try

            {
                containerDataValue = new ByteBufferBerDataValueReader(encoded).readDataValue();
            }
            catch (BerDataValueFormatException e)
            {
                throw new Asn1DecodingException("Failed to decode top-level data value", e);
            }

            if (containerDataValue == null)
            {
                throw new Asn1DecodingException("Empty input");
            }

            return parseSetOf<T>(containerDataValue);
        }

        private static T parse<T>(BerDataValue container)
        {
            if (container == null)
            {
                throw new ArgumentNullException(nameof(container));
            }

            Asn1Type dataType = getContainerAsn1Type<T>();
            switch (dataType)
            {
                case Asn1Type.CHOICE:
                    return parseChoice<T>(container);

                case Asn1Type.SEQUENCE:
                {
                    int expectedTagClass = BerEncoding.TAG_CLASS_UNIVERSAL;
                    int expectedTagNumber = BerEncoding.getTagNumber(dataType);
                    if ((container.getTagClass() != expectedTagClass)
                        || (container.getTagNumber() != expectedTagNumber))
                    {
                        throw new Asn1UnexpectedTagException(
                            "Unexpected data value read as " + typeof(T).FullName
                                                             + ". Expected " + BerEncoding.tagClassAndNumberToString(
                                                                 expectedTagClass, expectedTagNumber)
                                                             + ", but read: " + BerEncoding.tagClassAndNumberToString(
                                                                 container.getTagClass(), container.getTagNumber()));
                    }

                    return parseSequence<T>(container);
                }
                case Asn1Type.UNENCODED_CONTAINER:
                    return parseSequence<T>(container, true);
                default:
                    throw new Asn1DecodingException("Parsing container " + dataType + " not supported");
            }
        }

        private static object parseChoice(BerDataValue dataValue, Type containerClass)
        {
            return ParseChoiceMethodInfo.MakeGenericMethod(containerClass)
                .Invoke(null, new object[] { dataValue });
        }

        private static readonly MethodInfo ParseChoiceMethodInfo = typeof(Asn1BerParser)
            .GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
            .Single(m => m.Name == nameof(parseChoice) && m.IsGenericMethodDefinition && m.GetParameters().Length == 1);

        private static T parseChoice<T>(BerDataValue dataValue)
        {
            List<AnnotatedField> fields = getAnnotatedFields<T>();
            if (fields.Count == 0)
            {
                throw new Asn1DecodingException(
                    "No fields annotated with " + typeof(Asn1FieldAttribute).FullName
                                                + " in CHOICE class " + typeof(T).FullName);
            }

            // Check that class + tagNumber don't clash between the choices
            for (int i = 0; i < fields.Count - 1; i++)
            {
                AnnotatedField f1 = fields[i];
                int tagNumber1 = f1.getBerTagNumber();
                int tagClass1 = f1.getBerTagClass();
                for (int j = i + 1; j < fields.Count; j++)
                {
                    AnnotatedField f2 = fields[j];
                    int tagNumber2 = f2.getBerTagNumber();
                    int tagClass2 = f2.getBerTagClass();
                    if ((tagNumber1 == tagNumber2) && (tagClass1 == tagClass2))
                    {
                        throw new Asn1DecodingException(
                            "CHOICE fields are indistinguishable because they have the same tag"
                            + " class and number: " + typeof(T).FullName
                            + "." + f1.getField().Name
                            + " and ." + f2.getField().Name);
                    }
                }
            }

            // Instantiate the container object / result
            T obj;
            try
            {
                obj = Activator.CreateInstance<T>();
            }
            catch (Exception e)
            {
                throw new Asn1DecodingException("Failed to instantiate " + typeof(T).FullName, e);
            }

            // Set the matching field's value from the data value
            foreach (AnnotatedField field in fields)
            {
                try
                {
                    field.setValueFrom(dataValue, obj);
                    return obj;
                }
                catch (Asn1UnexpectedTagException expected)
                {
                    // not a match
                }
            }

            throw new Asn1DecodingException(
                "No options of CHOICE " + typeof(T).FullName + " matched");
        }

        private static object parseSequence(BerDataValue container, Type type)
        {
            return parseSequenceMethodInfo.MakeGenericMethod(type).Invoke(null, new object[] { container });
        }

        private static readonly MethodInfo parseSequenceMethodInfo = typeof(Asn1BerParser)
            .GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
            .Single(m =>
                m.Name == nameof(parseSequence) && m.IsGenericMethodDefinition && m.GetParameters().Length == 1);

        private static T parseSequence<T>(BerDataValue container)
        {
            return parseSequence<T>(container, false);
        }

        private static T parseSequence<T>(BerDataValue container, bool isUnencodedContainer)
        {
            List<AnnotatedField> fields = getAnnotatedFields<T>();
            fields.Sort((f1, f2) => f1.getAnnotation().Index - f2.getAnnotation().Index);
            // Check that there are no fields with the same index
            if (fields.Count > 1)
            {
                AnnotatedField lastField = null;
                foreach (AnnotatedField field in fields)
                {
                    if ((lastField != null)
                        && (lastField.getAnnotation().Index == field.getAnnotation().Index))
                    {
                        throw new Asn1DecodingException(
                            "Fields have the same index: " + typeof(T).FullName
                                                           + "." + lastField.getField().Name
                                                           + " and ." + field.getField().Name);
                    }

                    lastField = field;
                }
            }

            // Instantiate the container object / result
            T t;
            try

            {
                t = Activator.CreateInstance<T>();
            }
            catch (Exception e)
            {
                throw new Asn1DecodingException("Failed to instantiate " + typeof(T).FullName, e);
            }

            // Parse fields one by one. A complication is that there may be optional fields.
            int nextUnreadFieldIndex = 0;
            BerDataValueReader elementsReader = container.contentsReader();
            while (nextUnreadFieldIndex < fields.Count)
            {
                BerDataValue dataValue;
                try
                {
                    // if this is the first field of an unencoded container then the entire contents of
                    // the container should be used when assigning to this field.
                    if (isUnencodedContainer && nextUnreadFieldIndex == 0)
                    {
                        dataValue = container;
                    }
                    else
                    {
                        dataValue = elementsReader.readDataValue();
                    }
                }
                catch (BerDataValueFormatException e)
                {
                    throw new Asn1DecodingException("Malformed data value", e);
                }

                if (dataValue == null)
                {
                    break;
                }

                for (int i = nextUnreadFieldIndex; i < fields.Count; i++)
                {
                    AnnotatedField field = fields[i];
                    try
                    {
                        if (field.isOptional())
                        {
                            // Optional field -- might not be present and we may thus be trying to set
                            // it from the wrong tag.
                            try
                            {
                                field.setValueFrom(dataValue, t);
                                nextUnreadFieldIndex = i + 1;
                                break;
                            }
                            catch (Asn1UnexpectedTagException e)
                            {
                                // This field is not present, attempt to use this data value for the
                                // next / iteration of the loop
                                continue;
                            }
                        }
                        else
                        {
                            // Mandatory field -- if we can't set its value from this data value, then
                            // it's an error
                            field.setValueFrom(dataValue, t);
                            nextUnreadFieldIndex = i + 1;
                            break;
                        }
                    }
                    catch (Asn1DecodingException e)
                    {
                        throw new Asn1DecodingException(
                            "Failed to parse " + typeof(T).FullName
                                               + "." + field.getField().Name,
                            e);
                    }
                }
            }

            return t;
        }

        // NOTE: This method returns List rather than Set because ASN.1 SET_OF does require uniqueness
        // of elements -- it's an unordered collection.
        private static readonly MethodInfo ParseSetOfGenericMethod = typeof(Asn1BerParser)
            .GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
            .Single(m => m.Name == nameof(parseSetOf) && m.IsGenericMethodDefinition && m.GetParameters().Length == 1);

        private static IList parseSetOf(BerDataValue container, Type type)
        {
            return (IList)ParseSetOfGenericMethod.MakeGenericMethod(type)
                .Invoke(null, new[] { container });
        }

        private static List<T> parseSetOf<T>(BerDataValue container)
        {
            var result = new List<T>();

            BerDataValueReader elementsReader = container.contentsReader();
            while (true)
            {
                BerDataValue dataValue;
                try
                {
                    dataValue = elementsReader.readDataValue();
                }
                catch (BerDataValueFormatException e)
                {
                    throw new Asn1DecodingException("Malformed data value", e);
                }

                if (dataValue == null)
                {
                    break;
                }

                T element;
                if (typeof(ByteBuffer) == typeof(T))
                {
                    element = (T)(object)dataValue.getEncodedContents();
                }
                else if (typeof(Asn1OpaqueObject) == typeof(T))
                {
                    element = (T)(object)new Asn1OpaqueObject(dataValue.getEncoded());
                }
                else
                {
                    element = parse<T>(dataValue);
                }

                result.Add(element);
            }

            return result;
        }

        private static Asn1Type getContainerAsn1Type<T>()
        {
            var containerClass = typeof(T);
            var containerAnnotation = containerClass.GetCustomAttribute<Asn1ClassAttribute>();
            if (containerAnnotation == null)
            {
                throw new Asn1DecodingException(
                    containerClass.FullName + " is not annotated with "
                                            + typeof(Asn1ClassAttribute).FullName);
            }

            switch (containerAnnotation.Type)
            {
                case Asn1Type.CHOICE:
                case Asn1Type.SEQUENCE:
                case Asn1Type.UNENCODED_CONTAINER:
                    return containerAnnotation.Type;
                default:
                    throw new Asn1DecodingException(
                        "Unsupported ASN.1 container annotation type: "
                        + containerAnnotation.Type);
            }
        }

        private static Type getElementType(FieldInfo field)
        {
            if (!field.FieldType.IsConstructedGenericType)
            {
                throw new Asn1DecodingException("Not a container type: " + field.FieldType.FullName);
            }

            return field.FieldType.GenericTypeArguments[0];
        }

        private sealed class AnnotatedField
        {
            private readonly FieldInfo mField;
            private readonly Asn1FieldAttribute mAnnotation;
            private readonly Asn1Type mDataType;
            private readonly Asn1TagClass mTagClass;
            private readonly int mBerTagClass;
            private readonly int mBerTagNumber;
            private readonly Asn1Tagging mTagging;
            private readonly bool mOptional;

            public AnnotatedField(FieldInfo field, Asn1FieldAttribute annotation)
            {
                mField = field;
                mAnnotation = annotation;
                mDataType = annotation.Type;

                Asn1TagClass tagClass = annotation.Cls;
                if (tagClass == Asn1TagClass.AUTOMATIC)
                {
                    if (annotation.TagNumber != -1)
                    {
                        tagClass = Asn1TagClass.CONTEXT_SPECIFIC;
                    }
                    else
                    {
                        tagClass = Asn1TagClass.UNIVERSAL;
                    }
                }

                mTagClass = tagClass;
                mBerTagClass = BerEncoding.getTagClass(mTagClass);

                int tagNumber;
                if (annotation.TagNumber != -1)
                {
                    tagNumber = annotation.TagNumber;
                }

                else if ((mDataType == Asn1Type.CHOICE) || (mDataType == Asn1Type.ANY))
                {
                    tagNumber = -1;
                }

                else
                {
                    tagNumber = BerEncoding.getTagNumber(mDataType);
                }

                mBerTagNumber = tagNumber;

                mTagging = annotation.Tagging;
                if (((mTagging == Asn1Tagging.EXPLICIT) || (mTagging == Asn1Tagging.IMPLICIT))
                    && (annotation.TagNumber == -1))
                {
                    throw new Asn1DecodingException(
                        "Tag number must be specified when tagging mode is " + mTagging);
                }

                mOptional = annotation.Optional;
            }

            public FieldInfo getField()
            {
                return mField;
            }

            public Asn1FieldAttribute getAnnotation()
            {
                return mAnnotation;
            }

            public bool isOptional()
            {
                return mOptional;
            }

            public int getBerTagClass()
            {
                return mBerTagClass;
            }

            public int getBerTagNumber()
            {
                return mBerTagNumber;
            }

            public void setValueFrom(BerDataValue dataValue, Object obj)
            {
                int readTagClass = dataValue.getTagClass();
                if (mBerTagNumber != -1)
                {
                    int readTagNumber = dataValue.getTagNumber();
                    if ((readTagClass != mBerTagClass) || (readTagNumber != mBerTagNumber))
                    {
                        throw new Asn1UnexpectedTagException(
                            "Tag mismatch. Expected: "
                            + BerEncoding.tagClassAndNumberToString(mBerTagClass, mBerTagNumber)
                            + ", but found "
                            + BerEncoding.tagClassAndNumberToString(readTagClass, readTagNumber));
                    }
                }

                else
                {
                    if (readTagClass != mBerTagClass)
                    {
                        throw new Asn1UnexpectedTagException(
                            "Tag mismatch. Expected class: "
                            + BerEncoding.tagClassToString(mBerTagClass)
                            + ", but found "
                            + BerEncoding.tagClassToString(readTagClass));
                    }
                }

                if (mTagging == Asn1Tagging.EXPLICIT)
                {
                    try
                    {
                        dataValue = dataValue.contentsReader().readDataValue();
                    }
                    catch (BerDataValueFormatException e)
                    {
                        throw new Asn1DecodingException(
                            "Failed to read contents of EXPLICIT data value", e);
                    }
                }

                BerToJavaConverter.setFieldValue(obj, mField, mDataType, dataValue);
            }
        }

        private class Asn1UnexpectedTagException : Asn1DecodingException
        {
            public Asn1UnexpectedTagException(String message) : base(message)
            {
            }
        }

        private static String oidToString(ByteBuffer encodedOid)
        {
            if (!encodedOid.hasRemaining())
            {
                throw new Asn1DecodingException("Empty OBJECT IDENTIFIER");
            }

            // First component encodes the first two nodes, X.Y, as X * 40 + Y, with 0 <= X <= 2
            long firstComponent = decodeBase128UnsignedLong(encodedOid);
            int firstNode = (int)Math.Min(firstComponent / 40, 2);
            long secondNode = firstComponent - firstNode * 40;
            StringBuilder result = new StringBuilder();
            result.Append(firstNode.ToString()).Append('.')
                .Append(secondNode.ToString());

            // Each consecutive node is encoded as a separate component
            while (encodedOid.hasRemaining())
            {
                long node = decodeBase128UnsignedLong(encodedOid);
                result.Append('.').Append(node.ToString());
            }

            return result.ToString();
        }

        private static long decodeBase128UnsignedLong(ByteBuffer encoded)
        {
            if (!encoded.hasRemaining())
            {
                return 0;
            }

            long result = 0;
            while (encoded.hasRemaining())
            {
                if (result > long.MaxValue >> 7)
                {
                    throw new Asn1DecodingException("Base-128 number too large");
                }

                int b = encoded.get() & 0xff;
                result <<= 7;
                result |= b & 0x7f;
                if ((b & 0x80) == 0)
                {
                    return result;
                }
            }

            throw new Asn1DecodingException(
                "Truncated base-128 encoded input: missing terminating byte, with highest bit not"
                + " set");
        }

        private static BigInteger integerToBigInteger(ByteBuffer encoded)
        {
            if (!encoded.hasRemaining())
            {
                return BigInteger.Zero;
            }

            var raw = ByteBufferUtils.toByteArray(encoded);
            Array.Reverse(raw);
            return new BigInteger(raw);
        }

        private static int integerToInt(ByteBuffer encoded)
        {
            BigInteger value = integerToBigInteger(encoded);
            if (value.CompareTo(new BigInteger(int.MinValue)) < 0
                || value.CompareTo(new BigInteger(int.MaxValue)) > 0)
            {
                throw new Asn1DecodingException(
                    String.Format("INTEGER cannot be represented as int: {0}", value));
            }

            return (int)value;
        }

        private static long integerToLong(ByteBuffer encoded)
        {
            BigInteger value = integerToBigInteger(encoded);
            if (value.CompareTo(new BigInteger(long.MinValue)) < 0
                || value.CompareTo(new BigInteger(long.MaxValue)) > 0)
            {
                throw new Asn1DecodingException(
                    String.Format("INTEGER cannot be represented as long: {0}", value));
            }

            return (long)value;
        }

        private static List<AnnotatedField> getAnnotatedFields<T>()
        {
            FieldInfo[] declaredFields = typeof(T).GetFields();

            List<AnnotatedField> result = new List<AnnotatedField>(declaredFields.Length);
            foreach (var field in declaredFields)
            {
                Asn1FieldAttribute annotation = field.GetCustomAttribute<Asn1FieldAttribute>();
                if (annotation == null)
                {
                    continue;
                }

                if (field.IsStatic)
                {
                    throw new Asn1DecodingException(
                        typeof(Asn1FieldAttribute).FullName + " used on a static field: "
                                                            + typeof(T).FullName + "." + field.Name);
                }

                AnnotatedField annotatedField;
                try
                {
                    annotatedField = new AnnotatedField(field, annotation);
                }
                catch (Asn1DecodingException e)
                {
                    throw new Asn1DecodingException(
                        "Invalid ASN.1 annotation on "
                        + typeof(T).FullName + "." + field.Name,
                        e);
                }

                result.Add(annotatedField);
            }

            return result;
        }

        private static class BerToJavaConverter
        {
            public static void setFieldValue(object obj, FieldInfo field, Asn1Type type, BerDataValue dataValue)
            {
                try
                {
                    switch (type)
                    {
                        case Asn1Type.SET_OF:
                        case Asn1Type.SEQUENCE_OF:
                            if (typeof(Asn1OpaqueObject) == field.FieldType)
                            {
                                field.SetValue(obj, convert(type, dataValue, field.FieldType));
                            }
                            else
                            {
                                field.SetValue(obj, parseSetOf(dataValue, getElementType(field)));
                            }

                            return;
                        default:
                            field.SetValue(obj, convert(type, dataValue, field.FieldType));
                            break;
                    }
                }
                catch (Exception e)
                {
                    throw new Asn1DecodingException(
                        "Failed to set value of " + obj.GetType().FullName
                                                  + "." + field.Name,
                        e);
                }
            }

            private static readonly byte[] EMPTY_BYTE_ARRAY = new byte[0];

            public static object convert(
                Asn1Type sourceType,
                BerDataValue dataValue,
                Type targetType)
            {
                if (typeof(ByteBuffer) == targetType)
                {
                    return dataValue.getEncodedContents();
                }
                else if (typeof(byte[]) == targetType)
                {
                    ByteBuffer resultBuf = dataValue.getEncodedContents();
                    if (!resultBuf.hasRemaining())
                    {
                        return EMPTY_BYTE_ARRAY;
                    }

                    byte[] result = new byte[resultBuf.remaining()];
                    resultBuf.get(result);
                    return result;
                }
                else if (typeof(Asn1OpaqueObject) == targetType)
                {
                    return new Asn1OpaqueObject(dataValue.getEncoded());
                }

                ByteBuffer encodedContents = dataValue.getEncodedContents();
                switch (sourceType)
                {
                    case Asn1Type.INTEGER:
                        if ((typeof(int?) == targetType))
                        {
                            return (int?)integerToInt(encodedContents);
                        }
                        else if ((typeof(int) == targetType))
                        {
                            return integerToInt(encodedContents);
                        }
                        else if (typeof(long?) == targetType)
                        {
                            return (long?)integerToLong(encodedContents);
                        }
                        else if (typeof(long) == targetType)
                        {
                            return integerToLong(encodedContents);
                        }
                        else if (typeof(BigInteger?) == targetType)
                        {
                            return integerToBigInteger(encodedContents);
                        }
                        else if (typeof(BigInteger) == targetType)
                        {
                            return integerToBigInteger(encodedContents);
                        }

                        break;
                    case Asn1Type.OBJECT_IDENTIFIER:
                        if (typeof(string) == targetType)
                        {
                            return oidToString(encodedContents);
                        }

                        break;
                    case Asn1Type.UTC_TIME:
                    case Asn1Type.GENERALIZED_TIME:
                        if (typeof(string) == targetType)
                        {
                            return Encoding.Default.GetString(ByteBufferUtils.toByteArray(encodedContents));
                        }

                        break;
                    case Asn1Type.BOOLEAN:
                        // A boolean should be encoded in a single byte with a value of 0 for false and
                        // any non-zero value for true.
                        if (typeof(bool) == targetType || typeof(bool?) == targetType)
                        {
                            if (encodedContents.remaining() != 1)
                            {
                                throw new Asn1DecodingException(
                                    "Incorrect encoded size of boolean value: "
                                    + encodedContents.remaining());
                            }

                            bool result;
                            if (encodedContents.get() == 0)
                            {
                                result = false;
                            }
                            else
                            {
                                result = true;
                            }

                            return result;
                        }

                        break;
                    case Asn1Type.SEQUENCE:
                    {
                        Asn1ClassAttribute containerAnnotation =
                            targetType.GetCustomAttribute<Asn1ClassAttribute>();
                        if ((containerAnnotation != null)
                            && (containerAnnotation.Type == Asn1Type.SEQUENCE))
                        {
                            return parseSequence(dataValue, targetType);
                        }

                        break;
                    }
                    case Asn1Type.CHOICE:
                    {
                        Asn1ClassAttribute containerAnnotation =
                            targetType.GetCustomAttribute<Asn1ClassAttribute>();
                        if ((containerAnnotation != null)
                            && (containerAnnotation.Type == Asn1Type.CHOICE))
                        {
                            return parseChoice(dataValue, targetType);
                        }

                        break;
                    }
                    default:
                        break;
                }

                throw new Asn1DecodingException(
                    "Unsupported conversion: ASN.1 " + sourceType + " to " + targetType.FullName);
            }
        }
    }
}