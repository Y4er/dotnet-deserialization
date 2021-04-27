# dotnet deserialization

本系列是笔者从0到1对dotnet反序列化进行系统学习的笔记，其中涉及官方的反序列化formatter和第三方库的反序列化组件(如Json.net等)，其中穿插一些ysoserial.net的使用及原理，以及一些dotnet的知识点。

笔者也是初入茅庐，如果文章表述或讲解有错，请不吝赐教。

# 参考

全系列文章参考以下内容

1. [ysoserial.net](https://github.com/pwntester/ysoserial.net)
2. [docs.microsoft.com](https://docs.microsoft.com/zh-cn/dotnet/standard/serialization/)
3. https://github.com/Ivan1ee/NET-Deserialize

着重参考[@Ivan1ee](https://github.com/Ivan1ee)师傅的文章及其Github，以及微软文档和一些国外的议题、paper，还有[@pwntester](https://github.com/pwntester)的文章。

# 目录

1. [dotnet serialize 101](./dotnet-serialize-101.md)

   讲解dotnet序列化基础及其生命周期

2. [XmlSerializer](./XmlSerializer.md)

   讲解xmlserializer基础、ysoserial.net ObjectDataProvider攻击链以及XamlReader.Parse()

3. [BinaryFormatter](./BinaryFormatter.md)

   讲解二进制formatter基础及TextFormattingRunProperties、DataSet、TypeConfuseDelegate攻击链
   
4. [SoapFormatter](./SoapFormatter.md)

   讲解soap格式流的反序列化漏洞及ActivitySurrogateSelector、ActivitySurrogateSelectorFromFile、ActivitySurrogateDisableTypeCheck、AxHostState攻击链和Kentico CMS的RCE
   
5. [LosFormatter](./LosFormatter.md)

   讲解LosFormatter反序列化，以及ClaimsIdentity、WindowsIdentity、WindowsClaimsIdentity、SessionSecurityToken攻击链。

6. [ObjectStateFormatter](./ObjectStateFormatter.md)

   讲解ObjectStateFormatter反序列化以及RolePrincipal、WindowsPrincipal攻击链。

7. DataContractSerializer

8. NetDataContractSerializer

9. Json.Net

10. Fastjson

11. JavaScriptSerializer

12. .NET Remoting

# gadget

```
== GADGETS ==
        (-) ActivitySurrogateDisableTypeCheck [Disables 4.8+ type protections for ActivitySurrogateSelector, command is ignored]
                Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer , SoapFormatter
        (-) ActivitySurrogateSelector [This gadget ignores the command parameter and executes the constructor of ExploitClass class] (supports extra options: use the '--fullhelp' argument to view)
                Formatters: BinaryFormatter (2) , LosFormatter , SoapFormatter
        (-) ActivitySurrogateSelectorFromFile [Another variant of the ActivitySurrogateSelector gadget. This gadget interprets the command parameter as path to the .cs file that should be compiled as exploit class. Use semicolon to separate the file from additionally required assemblies, e. g., '-c ExploitClass.cs;System.Windows.Forms.dll'] (supports extra options: use the '--fullhelp' argument to view)
                Formatters: BinaryFormatter (2) , LosFormatter , SoapFormatter
        (-) AxHostState
                Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer , SoapFormatter
        (*) ClaimsIdentity
                Formatters: BinaryFormatter , LosFormatter , SoapFormatter
        (-) DataSet
                Formatters: BinaryFormatter , LosFormatter , SoapFormatter
        (-) ObjectDataProvider (supports extra options: use the '--fullhelp' argument to view)
                Formatters: DataContractSerializer (2) , FastJson , FsPickler , JavaScriptSerializer , Json.Net , SharpSerializerBinary , SharpSerializerXml , Xaml (4) , XmlSerializer (2) , YamlDotNet < 5.0.0
        (*) PSObject [Target must run a system not patched for CVE-2017-8565 (Published: 07/11/2017)]
                Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer , SoapFormatter
        (*) RolePrincipal
                Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
        (*) SessionSecurityToken
                Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
        (*) SessionViewStateHistoryItem
                Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
        (-) TextFormattingRunProperties [This normally generates the shortest payload] (supports extra options: use the '--fullhelp' argument to view)
                Formatters: BinaryFormatter , DataContractSerializer , LosFormatter , NetDataContractSerializer , SoapFormatter
        (*) ToolboxItemContainer
                Formatters: BinaryFormatter , LosFormatter , SoapFormatter
        (-) TypeConfuseDelegate
                Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer
        (-) TypeConfuseDelegateMono [Tweaked TypeConfuseDelegate gadget to work with Mono]
                Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer
        (*) WindowsClaimsIdentity [Requires Microsoft.IdentityModel.Claims namespace (not default GAC)] (supports extra options: use the '--fullhelp' argument to view)
                Formatters: BinaryFormatter (3) , DataContractSerializer (2) , Json.Net (2) , LosFormatter (3) , NetDataContractSerializer (3) , SoapFormatter (2)
        (*) WindowsIdentity
                Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
        (*) WindowsPrincipal
                Formatters: BinaryFormatter , DataContractJsonSerializer , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
```

# 关于

ID:Y4er

Blog:[Y4er.com](http://Y4er.com)

Twitter:[@Y4er_ChaBug](https://twitter.com/Y4er_ChaBug)