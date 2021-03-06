﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using OpenCover.Framework;

namespace OpenCover.Test.Framework
{
    [TestFixture]
    public class FilterTests
    {
        #region TestData for AddFilter tests

        public class AssemblyClassData
        {
            public string AssemblyClass { get; set; }
            public string AssemblyResult { get; set; }
            public string ClassResult { get; set; }
            public FilterType FilterTypeResult { get; set; }
        }

#pragma warning disable 169

        private string[] _invalidAssemblyClassPairs = new[] { "Garbage", "+[]", "-[ ]", "[ ", " ]", "+[]]", "-[][", @"-[\]", @"+[X]\", "-[X]]", "+[X][" };

        private AssemblyClassData[] _assemblyClassPairs = new[]
                                                              {
                                                                  new AssemblyClassData()
                                                                      {
                                                                          AssemblyClass = "+[System]Console",
                                                                          AssemblyResult = "System",
                                                                          ClassResult = "Console",
                                                                          FilterTypeResult = FilterType.Inclusion, 
                                                                      },
                                                                  new AssemblyClassData()
                                                                      {
                                                                          AssemblyClass = "+[System]",
                                                                          AssemblyResult = "System",
                                                                          ClassResult = "",
                                                                          FilterTypeResult = FilterType.Inclusion, 
                                                                      },
                                                                  new AssemblyClassData()
                                                                      {
                                                                          AssemblyClass = "-[System.*]Console",
                                                                          AssemblyResult = @"System\..*",
                                                                          ClassResult = "Console",
                                                                          FilterTypeResult = FilterType.Exclusion, 
                                                                      },
                                                                  new AssemblyClassData()
                                                                      {
                                                                          AssemblyClass = "+[System]Console.*",
                                                                          AssemblyResult = "System",
                                                                          ClassResult = @"Console\..*",
                                                                          FilterTypeResult = FilterType.Inclusion, 
                                                                      },
                                                                  new AssemblyClassData()
                                                                      {
                                                                          AssemblyClass = "-[System.*]Console.*",
                                                                          AssemblyResult = @"System\..*",
                                                                          ClassResult = @"Console\..*",
                                                                          FilterTypeResult = FilterType.Exclusion, 
                                                                      }
                                                              };
#pragma warning restore 169   
        #endregion

        [Test]
        public void AddFilter_ThrowsException_WhenInvalid_AssemblyClassPair(
            [ValueSource("_invalidAssemblyClassPairs")]string assemblyClassPair)
        {
            // arrange
            var filter = new Filter();

            // act/assert
            Assert.Catch<InvalidOperationException>(() => filter.AddFilter(assemblyClassPair), 
                "'{0}' should be invalid", assemblyClassPair);     
        }

        [Test]
        public void AddFilter_Adds_ValidAssemblyClassPair(
            [ValueSource("_assemblyClassPairs")]AssemblyClassData assemblyClassPair)
        {
            // arrange
            var filter = new Filter();

            // act
            filter.AddFilter(assemblyClassPair.AssemblyClass);

            // assert
            Assert.AreEqual(1, assemblyClassPair.FilterTypeResult == FilterType.Inclusion ? 
                filter.InclusionFilter.Count : filter.ExclusionFilter.Count);

            Assert.AreEqual(assemblyClassPair.AssemblyResult, assemblyClassPair.FilterTypeResult == FilterType.Inclusion ?
                filter.InclusionFilter[0].Key : filter.ExclusionFilter[0].Key);

            Assert.AreEqual(assemblyClassPair.ClassResult, assemblyClassPair.FilterTypeResult == FilterType.Inclusion ?
                filter.InclusionFilter[0].Value : filter.ExclusionFilter[0].Value);
        }

        #region Test Data or UseAssembly tests

        public class UseAssemblyData
        {
            public string[] Filters { get; set; }
            public string Assembly { get; set; }
            public bool ExpectedResult { get; set; }
        }

        private UseAssemblyData[] _useAssemblyData = new[]
                                                         {
                                                             new UseAssemblyData()
                                                                 {
                                                                     Filters = new string[0],
                                                                     Assembly = "System.Debug",
                                                                     ExpectedResult = false
                                                                 },
                                                                 new UseAssemblyData()
                                                                 {
                                                                     Filters = new [] {"-[System.*]R*"},
                                                                     Assembly = "System.Debug",
                                                                     ExpectedResult = true
                                                                 },
                                                                 new UseAssemblyData()
                                                                 {
                                                                     Filters = new [] {"-[System.*]*"},
                                                                     Assembly = "System.Debug",
                                                                     ExpectedResult = false
                                                                 },
                                                                 new UseAssemblyData()
                                                                 {
                                                                     Filters = new [] {"+[System.*]*"},
                                                                     Assembly = "System.Debug",
                                                                     ExpectedResult = true
                                                                 },
                                                                 new UseAssemblyData()
                                                                 {
                                                                     Filters = new [] {"-[mscorlib]*", "-[System.*]*", "+[*]*"},
                                                                     Assembly = "mscorlib",
                                                                     ExpectedResult = false
                                                                 },
                                                                 new UseAssemblyData()
                                                                 {
                                                                     Filters = new [] {"+[XYZ]*"},
                                                                     Assembly = "XYZ",
                                                                     ExpectedResult = true
                                                                 },
                                                                 new UseAssemblyData()
                                                                 {
                                                                     Filters = new [] {"+[XYZ]*"},
                                                                     Assembly = "XYZA",
                                                                     ExpectedResult = false
                                                                 }
                                                         };
        #endregion

        [Test]
        public void UseAssembly_Tests(
            [ValueSource("_useAssemblyData")]UseAssemblyData data)
        {
            // arrange
            var filter = new Filter();
            data.Filters.ToList().ForEach(filter.AddFilter);

            // act
            var result = filter.UseAssembly(data.Assembly);

            // result
            Assert.AreEqual(data.ExpectedResult, result, 
                "Filter: '{0}' Assembly: {1} => Expected: {2}", 
                string.Join(",", data.Filters, data.Assembly, data.ExpectedResult));
        }

        #region Test Data for InstrumentClass tests

        public class InstrumentClassData
        {
            public string[] Filters { get; set; }
            public string Assembly { get; set; }
            public string Class { get; set; }
            public bool ExpectedResult { get; set; }
        }

        private InstrumentClassData[] _instrumentClassData = new[]
                                                                 {
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"+[XYZ]*"},
                                                                             Assembly = "XYZ",
                                                                             Class = "Namespace.Class",
                                                                             ExpectedResult = true
                                                                         },
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"+[XYZ]A*"},
                                                                             Assembly = "XYZ",
                                                                             Class = "Namespace.Class",
                                                                             ExpectedResult = false
                                                                         },
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"+[XYZ*]A*"},
                                                                             Assembly = "XYZA",
                                                                             Class = "Namespace.Class",
                                                                             ExpectedResult = false
                                                                         },
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"+[XYZ]A*"},
                                                                             Assembly = "XYZA",
                                                                             Class = "Namespace.Class",
                                                                             ExpectedResult = false
                                                                         },
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"+[XYZ]*Class"},
                                                                             Assembly = "XYZ",
                                                                             Class = "Namespace.Class",
                                                                             ExpectedResult = true
                                                                         },
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"+[XYZ]*Name"},
                                                                             Assembly = "XYZ",
                                                                             Class = "Namespace.Class",
                                                                             ExpectedResult = false
                                                                         },
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"+[XYZ]*space.C*"},
                                                                             Assembly = "XYZ",
                                                                             Class = "Namespace.Class",
                                                                             ExpectedResult = true
                                                                         },
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"-[XYZ*]*"},
                                                                             Assembly = "XYZA",
                                                                             Class = "Namespace.Class",
                                                                             ExpectedResult = false
                                                                         },
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"-[XYZ]*"},
                                                                             Assembly = "XYZ",
                                                                             Class = "Namespace.Class",
                                                                             ExpectedResult = false
                                                                         },
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"-[*]*"},
                                                                             Assembly = "XYZ",
                                                                             Class = "Namespace.Class",
                                                                             ExpectedResult = false
                                                                         },
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"-[X*Z]*"},
                                                                             Assembly = "XYZ",
                                                                             Class = "Namespace.Class",
                                                                             ExpectedResult = false
                                                                         },
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"-[XYZ]*Class"},
                                                                             Assembly = "XYZ",
                                                                             Class = "Namespace.Class",
                                                                             ExpectedResult = false
                                                                         },
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"-[XYZ]*Unknown"},
                                                                             Assembly = "XYZ",
                                                                             Class = "Namespace.Class",
                                                                             ExpectedResult = false
                                                                         },
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"+[*]*"},
                                                                             Assembly = "",
                                                                             Class = "Namespace.Class",
                                                                             ExpectedResult = false
                                                                         },
                                                                     new InstrumentClassData()
                                                                         {
                                                                             Filters = new[] {"+[*]*"},
                                                                             Assembly = "XYZ",
                                                                             Class = "",
                                                                             ExpectedResult = false
                                                                         }

                                                                 };
        #endregion

        [Test]
        public void InstrumentClass_Tests(
            [ValueSource("_instrumentClassData")]InstrumentClassData data)
        {
            //// arrange
            var filter = new Filter();
            data.Filters.ToList().ForEach(filter.AddFilter);

            // act
            var result = filter.InstrumentClass(data.Assembly, data.Class);

            // result
            Assert.AreEqual(data.ExpectedResult, result,
               "Filter: '{0}' Assembly: {1} Class: {2} => Expected: {3}", 
               string.Join(",", data.Filters, data.Assembly, data.Class, data.ExpectedResult));
        }
    }
}
