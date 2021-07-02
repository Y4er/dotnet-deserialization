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
   
4. [Nancy cookie反序列化](./Nancy.md) 及攻击链ToolboxItemContainer

5. [SoapFormatter](./SoapFormatter.md)

   讲解soap格式流的反序列化漏洞及ActivitySurrogateSelector、ActivitySurrogateSelectorFromFile、ActivitySurrogateDisableTypeCheck、AxHostState攻击链和Kentico CMS的RCE

6. [LosFormatter](./LosFormatter.md)

   讲解LosFormatter反序列化，以及ClaimsIdentity、WindowsIdentity、WindowsClaimsIdentity、SessionSecurityToken攻击链。

7. [ObjectStateFormatter](./ObjectStateFormatter.md)

   讲解ObjectStateFormatter反序列化以及RolePrincipal、WindowsPrincipal攻击链。

8. [DataContractSerializer](./DataContractSerializer.md)

   讲解DataContractSerializer反序列化、SessionViewStateHistoryItem攻击链，以及对DataContractResolver类型解析器的利用。

9. [NetDataContractSerializer](./NetDataContractSerializer.md)

   讲解NetDataContractSerializer反序列化以及PSObject攻击链

10. [DataContractJsonSerializer](./DataContractJsonSerializer.md)

    讲解DataContractJsonSerializer反序列化及IDataContractSurrogate接口

11. [JavaScriptSerializer](./JavaScriptSerializer.md)

    讲解JavaScriptSerializer反序列化

12. [Json.Net](./Json.Net.md)

    讲解了json.net反序列化，并结合实际案例 breeze CVE-2017-9424深入理解。

13. [Fastjson](./Fastjson.md)

    讲解fastjson反序列化漏洞

14. [.NET Remoting](./.NET%20Remoting.md)

    讲解.net remoting漏洞
    
15. [SharePoint CVE-2019-0604](./SharePoint-CVE-2019-0604.md)

16. [ViewState](./ViewState.md)

# 关于

ID:Y4er

Blog:[Y4er.com](http://Y4er.com)

Twitter:[@Y4er_ChaBug](https://twitter.com/Y4er_ChaBug)