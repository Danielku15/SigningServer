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
using System.Collections.ObjectModel;
using System.IO;
using System.Numerics;
using System.Reflection;
using System.Text;
using SigningServer.Android;
using SigningServer.Android.ApkSig.Internal.Asn1;
using SigningServer.Android.ApkSig.Internal.Asn1.Ber;

namespace SigningServer.Android.ApkSig.Internal.Asn1
{
    /**
     * Encoder of ASN.1 structures into DER-encoded form.
     *
     * <p>Structure is described to the encoder by providing a class annotated with {@link Asn1Class},
     * containing fields annotated with {@link Asn1Field}.
     */
    public static class Asn1DerEncoder
    {
        /**
         * Returns the DER-encoded form of the provided ASN.1 structure.
         *
         * @param container container to be encoded. The container's class must meet the following
         *        requirements:
         *        <ul>
         *        <li>The class must be annotated with {@link Asn1Class}.</li>
         *        <li>Member fields of the class which are to be encoded must be annotated with
         *            {@link Asn1Field} and be public.</li>
         *        </ul>
         *
         * @throws Asn1EncodingException if the input could not be encoded
         */
        public static byte[] encode(object container)
        {
            Type containerClass = container.GetType();
            var containerAnnotation = containerClass.GetCustomAttribute<Asn1ClassAttribute>();
            if (containerAnnotation == null)
            {
                throw new Asn1EncodingException(
                    containerClass.FullName + " not annotated with " + typeof(Asn1ClassAttribute).FullName);
            }

            Asn1Type containerType = containerAnnotation.Type;
            switch (containerType)
            {
                case Asn1Type.CHOICE:
                    return toChoice(container);
                case Asn1Type.SEQUENCE:
                    return toSequence(container);
                case Asn1Type.UNENCODED_CONTAINER:
                    return toSequence(container, true);
                default:
                    throw new Asn1EncodingException("Unsupported container type: " + containerType);
            }
        }

        private static byte[] toChoice(Object container)
        {
            Type containerClass = container.GetType();

            List<AnnotatedField> fields = getAnnotatedFields(container);
            if (fields.Count == 0)
            {
                throw new Asn1EncodingException(
                    "No fields annotated with " + typeof(Asn1FieldAttribute).FullName
                                                + " in CHOICE class " + containerClass.FullName);
            }

            AnnotatedField resultField = null;
            foreach (AnnotatedField field in fields)
            {
                var fieldValue = getMemberFieldValue(container, field.getField());
                if (fieldValue != null)
                {
                    if (resultField != null)
                    {
                        throw new Asn1EncodingException(
                            "Multiple non-null fields in CHOICE class " + containerClass.FullName
                                                                        + ": " + resultField.getField().Name
                                                                        + ", " + field.getField().Name);
                    }

                    resultField = field;
                }
            }

            if (resultField == null)
            {
                throw new Asn1EncodingException(
                    "No non-null fields in CHOICE class " + containerClass.FullName);
            }

            return resultField.toDer();
        }

        private static byte[] toSequence(Object container)
        {
            return toSequence(container, false);
        }

        private static byte[] toSequence(Object container, bool omitTag)
        {
            Type containerClass = container.GetType();
            List<AnnotatedField> fields = getAnnotatedFields(container);
            fields.Sort((f1, f2) => f1.getAnnotation().Index - f2.getAnnotation().Index);
            if (fields.Count > 1)
            {
                AnnotatedField lastField = null;
                foreach (AnnotatedField field in fields)
                {
                    if ((lastField != null)
                        && (lastField.getAnnotation().Index == field.getAnnotation().Index))
                    {
                        throw new Asn1EncodingException(
                            "Fields have the same index: " + containerClass.FullName
                                                           + "." + lastField.getField().Name
                                                           + " and ." + field.getField().Name);
                    }

                    lastField = field;
                }
            }

            List<byte[]> serializedFields = new List<byte[]>(fields.Count);

            int contentLen = 0;
            foreach (AnnotatedField field in fields)
            {
                byte[] serializedField;
                try
                {
                    serializedField = field.toDer();
                }
                catch (Asn1EncodingException e)
                {
                    throw new Asn1EncodingException(
                        "Failed to encode " + containerClass.FullName
                                            + "." + field.getField().Name,
                        e);
                }

                if (serializedField != null)
                {
                    serializedFields.Add(serializedField);
                    contentLen += serializedField.Length;
                }
            }

            if (omitTag)
            {
                byte[] unencodedResult = new byte[contentLen];
                int index = 0;
                foreach (byte[] serializedField in
                         serializedFields)
                {
                    Array.Copy(serializedField, 0, unencodedResult, index, serializedField.Length);
                    index += serializedField.Length;
                }

                return unencodedResult;
            }
            else
            {
                return createTag(
                    BerEncoding.TAG_CLASS_UNIVERSAL, true, BerEncoding.TAG_NUMBER_SEQUENCE,
                    serializedFields.ToArray());
            }
        }

        private static byte[] toSetOf(ICollection values, Asn1Type? elementType)
        {
            return toSequenceOrSetOf(values, elementType, true);
        }

        private static byte[] toSequenceOf(ICollection values, Asn1Type? elementType)
        {
            return toSequenceOrSetOf(values, elementType, false);
        }

        private static byte[] toSequenceOrSetOf(ICollection values, Asn1Type? elementType, bool toSet)
        {
            List<byte[]> serializedValues = new List<byte[]>(values.Count);
            foreach (var value in values)
            {
                serializedValues.Add(JavaToDerConverter.toDer(value, elementType, null));
            }

            int tagNumber;
            if (toSet)
            {
                if (serializedValues.Count > 1)
                {
                    serializedValues.Sort(ByteArrayLexicographicComparator.INSTANCE);
                }

                tagNumber = BerEncoding.TAG_NUMBER_SET;
            }

            else
            {
                tagNumber = BerEncoding.TAG_NUMBER_SEQUENCE;
            }

            return createTag(
                BerEncoding.TAG_CLASS_UNIVERSAL, true, tagNumber,
                serializedValues.ToArray());
        }

        /**
         * Compares two bytes arrays based on their lexicographic order. Corresponding elements of the
         * two arrays are compared in ascending order. Elements at out of range indices are assumed to
         * be smaller than the smallest possible value for an element.
         */
        private class ByteArrayLexicographicComparator : IComparer<byte[]>
        {
            public static readonly ByteArrayLexicographicComparator INSTANCE =
                new ByteArrayLexicographicComparator();

            public int Compare(byte[] arr1, byte[] arr2)
            {
                int commonLength = Math.Min(arr1.Length, arr2.Length);
                for (int i = 0; i < commonLength; i++)
                {
                    int diff = (arr1[i] & 0xff) - (arr2[i] & 0xff);
                    if (diff != 0)
                    {
                        return diff;
                    }
                }

                return arr1.Length - arr2.Length;
            }
        }

        private static List<AnnotatedField> getAnnotatedFields(Object container)
        {
            Type containerClass = container.GetType();
            var declaredFields = containerClass.GetFields();

            List<AnnotatedField> result = new List<AnnotatedField>(declaredFields.Length);
            foreach (var field in declaredFields)
            {
                var annotation = field.GetCustomAttribute<Asn1FieldAttribute>();
                if (annotation == null)
                {
                    continue;
                }

                if (field.IsStatic)
                {
                    throw new Asn1EncodingException(
                        typeof(Asn1FieldAttribute).FullName + " used on a static field: "
                                                            + containerClass.FullName + "." + field.Name);
                }

                AnnotatedField annotatedField;
                try
                {
                    annotatedField = new AnnotatedField(container, field, annotation);
                }
                catch (Asn1EncodingException e)
                {
                    throw new Asn1EncodingException(
                        "Invalid ASN.1 annotation on "
                        + containerClass.FullName + "." + field.Name,
                        e);
                }

                result.Add(annotatedField);
            }

            return result;
        }

        private static byte[] toInteger(int value)
        {
            return toInteger((long)value);
        }

        private static byte[] toInteger(long value)
        {
            return toInteger(new BigInteger(value));
        }

        private static byte[] toInteger(BigInteger value)
        {
            return createTag(
                BerEncoding.TAG_CLASS_UNIVERSAL, false, BerEncoding.TAG_NUMBER_INTEGER,
                value.ToByteArray());
        }

        private static byte[] toBoolean(bool value)
        {
            // A boolean should be encoded in a single byte with a value of 0 for false and any non-zero
            // value for true.
            byte[] result = new byte[1];
            if (value == false)
            {
                result[0] = 0;
            }
            else
            {
                result[0] = 1;
            }

            return createTag(BerEncoding.TAG_CLASS_UNIVERSAL, false, BerEncoding.TAG_NUMBER_BOOLEAN, result);
        }

        private static byte[] toOid(String oid)
        {
            var encodedValue = new MemoryStream();

            var nodes = oid.Split(new[] { "\\." }, StringSplitOptions.None);
            if (nodes.Length < 2)
            {
                throw new Asn1EncodingException(
                    "OBJECT IDENTIFIER must contain at least two nodes: " + oid);
            }

            int firstNode;
            try

            {
                firstNode = int.Parse(nodes[0]);
            }
            catch (FormatException e)
            {
                throw new Asn1EncodingException("Node #1 not numeric: " + nodes[0]);
            }

            if ((firstNode > 6) || (firstNode < 0))
            {
                throw new Asn1EncodingException("Invalid value for node #1: " + firstNode);
            }

            int secondNode;
            try
            {
                secondNode = int.Parse(nodes[1]);
            }
            catch (FormatException e)
            {
                throw new Asn1EncodingException("Node #2 not numeric: " + nodes[1]);
            }

            if ((secondNode >= 40) || (secondNode < 0))
            {
                throw new Asn1EncodingException("Invalid value for node #2: " + secondNode);
            }

            int firstByte = firstNode * 40 + secondNode;
            if (firstByte > 0xff)
            {
                throw new Asn1EncodingException(
                    "First two nodes out of range: " + firstNode + "." + secondNode);
            }

            encodedValue.WriteByte((byte)firstByte);
            for (int i = 2; i < nodes.Length; i++)
            {
                String nodeString = nodes[i];
                int node;
                try
                {
                    node = int.Parse(nodeString);
                }
                catch (FormatException e)
                {
                    throw new Asn1EncodingException("Node #" + (i + 1) + " not numeric: " + nodeString);
                }

                if (node < 0)
                {
                    throw new Asn1EncodingException("Invalid value for node #" + (i + 1) + ": " + node);
                }

                if (node <= 0x7f)
                {
                    encodedValue.WriteByte((byte)node);
                    continue;
                }

                if (node < 1 << 14)
                {
                    encodedValue.WriteByte((byte)(0x80 | (node >> 7)));
                    encodedValue.WriteByte((byte)(node & 0x7f));
                    continue;
                }

                if (node < 1 << 21)
                {
                    encodedValue.WriteByte((byte)(0x80 | (node >> 14)));
                    encodedValue.WriteByte((byte)(0x80 | ((node >> 7) & 0x7f)));
                    encodedValue.WriteByte((byte)(node & 0x7f));
                    continue;
                }

                throw new Asn1EncodingException("Node #" + (i + 1) + " too large: " + node);
            }

            return createTag(
                BerEncoding.TAG_CLASS_UNIVERSAL, false, BerEncoding.TAG_NUMBER_OBJECT_IDENTIFIER,
                encodedValue.ToArray());
        }

        private static Object getMemberFieldValue(Object obj, FieldInfo field)
        {
            try

            {
                return field.GetValue(obj);
            }
            catch
                (Exception e)
            {
                throw new Asn1EncodingException(
                    "Failed to read " + obj.GetType().FullName + "." + field.Name, e);
            }
        }

        private sealed class AnnotatedField
        {
            private readonly FieldInfo mField;
            private readonly Object mObject;
            private readonly Asn1FieldAttribute mAnnotation;
            private readonly Asn1Type mDataType;
            private readonly Asn1Type mElementDataType;
            private readonly Asn1TagClass mTagClass;
            private readonly int mDerTagClass;
            private readonly int mDerTagNumber;
            private readonly Asn1Tagging mTagging;
            private readonly bool mOptional;

            public AnnotatedField(Object obj, FieldInfo field, Asn1FieldAttribute annotation)

            {
                mObject = obj;
                mField = field;
                mAnnotation = annotation;
                mDataType = annotation.Type;

                mElementDataType = annotation.ElementType;

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
                mDerTagClass = BerEncoding.getTagClass(mTagClass);

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

                mDerTagNumber = tagNumber;

                mTagging = annotation.Tagging;
                if (((mTagging == Asn1Tagging.EXPLICIT) || (mTagging == Asn1Tagging.IMPLICIT))
                    && (annotation.TagNumber == -1))
                {
                    throw new Asn1EncodingException(
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

            public byte[] toDer()
            {
                Object fieldValue = getMemberFieldValue(mObject, mField);
                if (fieldValue == null)
                {
                    if (mOptional)
                    {
                        return null;
                    }

                    throw new Asn1EncodingException("Required field not set");
                }

                byte[] encoded = JavaToDerConverter.toDer(fieldValue, mDataType, mElementDataType);
                switch (mTagging)
                {
                    case Asn1Tagging.NORMAL:
                        return encoded;
                    case Asn1Tagging.EXPLICIT:
                        return createTag(mDerTagClass, true, mDerTagNumber, encoded);
                    case Asn1Tagging.IMPLICIT:
                        int originalTagNumber = BerEncoding.getTagNumber(encoded[0]);
                        if (originalTagNumber == 0x1f)
                        {
                            throw new Asn1EncodingException("High-tag-number form not supported");
                        }

                        if (mDerTagNumber >= 0x1f)
                        {
                            throw new Asn1EncodingException(
                                "Unsupported high tag number: " + mDerTagNumber);
                        }

                        encoded[0] = BerEncoding.setTagNumber(encoded[0], mDerTagNumber);
                        encoded[0] = BerEncoding.setTagClass(encoded[0], mDerTagClass);
                        return encoded;
                    default:
                        throw new ArgumentException("Unknown tagging mode: " + mTagging);
                }
            }
        }

        private static byte[] createTag(
            int tagClass, bool constructed, int tagNumber, params byte[][] contents)
        {
            if (tagNumber >= 0x1f)
            {
                throw new ArgumentException("High tag numbers not supported: " + tagNumber);
            }

            // tag class & number fit into the first byte
            byte firstIdentifierByte =
                (byte)((tagClass << 6) | (constructed ? 1 << 5 : 0) | tagNumber);

            int contentsLength = 0;
            foreach (byte[] c in contents)
            {
                contentsLength += c.Length;
            }

            int contentsPosInResult;
            byte[] result;
            if (contentsLength < 0x80)
            {
                // Length fits into one byte
                contentsPosInResult = 2;
                result = new byte[contentsPosInResult + contentsLength];
                result[0] = firstIdentifierByte;
                result[1] = (byte)contentsLength;
            }
            else
            {
                // Length is represented as multiple bytes
                // The low 7 bits of the first byte represent the number of length bytes (following the
                // first byte) in which the length is in big-endian base-256 form
                if (contentsLength <= 0xff)
                {
                    contentsPosInResult = 3;
                    result = new byte[contentsPosInResult + contentsLength];
                    result[1] = (byte)0x81; // 1 length byte
                    result[2] = (byte)contentsLength;
                }
                else if (contentsLength <= 0xffff)
                {
                    contentsPosInResult = 4;
                    result = new byte[contentsPosInResult + contentsLength];
                    result[1] = (byte)0x82; // 2 length bytes
                    result[2] = (byte)(contentsLength >> 8);
                    result[3] = (byte)(contentsLength & 0xff);
                }
                else if (contentsLength <= 0xffffff)
                {
                    contentsPosInResult = 5;
                    result = new byte[contentsPosInResult + contentsLength];
                    result[1] = (byte)0x83; // 3 length bytes
                    result[2] = (byte)(contentsLength >> 16);
                    result[3] = (byte)((contentsLength >> 8) & 0xff);
                    result[4] = (byte)(contentsLength & 0xff);
                }
                else
                {
                    contentsPosInResult = 6;
                    result = new byte[contentsPosInResult + contentsLength];
                    result[1] = (byte)0x84; // 4 length bytes
                    result[2] = (byte)(contentsLength >> 24);
                    result[3] = (byte)((contentsLength >> 16) & 0xff);
                    result[4] = (byte)((contentsLength >> 8) & 0xff);
                    result[5] = (byte)(contentsLength & 0xff);
                }

                result[0] = firstIdentifierByte;
            }

            foreach (byte[] c in contents)
            {
                Array.Copy(c, 0, result, contentsPosInResult, c.Length);
                contentsPosInResult += c.Length;
            }

            return result;
        }

        private static class JavaToDerConverter
        {
            public static byte[] toDer(Object source, Asn1Type? targetType, Asn1Type? targetElementType)
            {
                var sourceType = source.GetType();
                if (typeof(Asn1OpaqueObject) == sourceType)
                {
                    ByteBuffer buf = ((Asn1OpaqueObject)source).getEncoded();
                    byte[] result = new byte[buf.remaining()];
                    buf.get(result);
                    return result;
                }

                if ((targetType == null) || (targetType == Asn1Type.ANY))
                {
                    return encode(source);
                }

                switch (targetType)
                {
                    case Asn1Type.OCTET_STRING:
                    case Asn1Type.BIT_STRING:
                        byte[] value = null;
                        if (source is ByteBuffer)
                        {
                            ByteBuffer buf = (ByteBuffer)source;
                            value = new byte[buf.remaining()];
                            buf.slice().get(value);
                        }
                        else if (source is byte[])
                        {
                            value = (byte[])source;
                        }

                        if (value != null)
                        {
                            return createTag(
                                BerEncoding.TAG_CLASS_UNIVERSAL,
                                false,
                                BerEncoding.getTagNumber(targetType),
                                value);
                        }

                        break;
                    case Asn1Type.INTEGER:
                        if (source is int)
                        {
                            return toInteger((int)source);
                        }
                        else if (source is long)
                        {
                            return toInteger((long)source);
                        }
                        else if (source is BigInteger)
                        {
                            return toInteger((BigInteger)source);
                        }

                        break;
                    case Asn1Type.BOOLEAN:
                        if (source is bool)
                        {
                            return toBoolean((bool)(source));
                        }

                        break;
                    case Asn1Type.UTC_TIME:
                    case Asn1Type.GENERALIZED_TIME:
                        if (source is string)
                        {
                            return createTag(BerEncoding.TAG_CLASS_UNIVERSAL, false,
                                BerEncoding.getTagNumber(targetType), Encoding.Default.GetBytes((string)source));
                        }

                        break;
                    case Asn1Type.OBJECT_IDENTIFIER:
                        if (source is String)
                        {
                            return toOid((String)source);
                        }

                        break;
                    case Asn1Type.SEQUENCE:
                    {
                        Asn1ClassAttribute containerAnnotation =
                            sourceType.GetCustomAttribute<Asn1ClassAttribute>();
                        if ((containerAnnotation != null)
                            && (containerAnnotation.Type == Asn1Type.SEQUENCE))
                        {
                            return toSequence(source);
                        }

                        break;
                    }
                    case Asn1Type.CHOICE:
                    {
                        var containerAnnotation =
                            sourceType.GetCustomAttribute<Asn1ClassAttribute>();
                        if ((containerAnnotation != null)
                            && (containerAnnotation.Type == Asn1Type.CHOICE))
                        {
                            return toChoice(source);
                        }

                        break;
                    }
                    case Asn1Type.SET_OF:
                        return toSetOf((ICollection)source, targetElementType);
                    case Asn1Type.SEQUENCE_OF:
                        return toSequenceOf((ICollection)source, targetElementType);
                    default:
                        break;
                }

                throw new Asn1EncodingException(
                    "Unsupported conversion: " + sourceType.FullName + " to ASN.1 " + targetType);
            }
        }

        /** ASN.1 DER-encoded {@code NULL}. */
        public static readonly Asn1OpaqueObject ASN1_DER_NULL = new Asn1OpaqueObject(new byte[]
        {
            BerEncoding.TAG_NUMBER_NULL, 0
        });
    }
}