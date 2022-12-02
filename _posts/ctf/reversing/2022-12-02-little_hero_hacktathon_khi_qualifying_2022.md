---
title: Encryptor hackathon lhr Qualifier 2022
author: megachar0x01
date: 2022-12-02
categories: [Reversing, Dotnet, ctf]
---

Using strings.exe was able to findout its dotnet binary . Opening in dnspyx86 (32-bit binary). After navigating to main funcion we can see that form function is being called.

```c#
using System;
using System.Windows.Forms;

namespace Challenge
{
	internal static class Program
	{
		private static void Main()
		{
			Application.EnableVisualStyles();
			Application.SetCompatibleTextRenderingDefault(false);
			Application.Run(new Form1());
		}
	}
}


```

```c#
public Form1()
		{
			this.InitializeComponent();
		}

		private void Form1_Load(object sender, EventArgs e)
		{
		}

		private void label1_Click(object sender, EventArgs e)
		{
		}

		private void button1_Click(object sender, EventArgs e)
		{
			try
			{
				string text = this.textBox1.Text;
				int[] array = new int[]
				{
					0,
					70,
					0,
					77,
					0,
					67,
					0,
					68,
					0,
					127,
					0,
					91,
					0,
					89,
					0,
					45,
					0,
					87,
					0,
					86,
					0,
					85,
					0,
					63,
					0,
					120,
					0,
					96,
					0,
					62,
					0,
					58,
					0,
					118,
					0,
					34,
					0,
					38,
					0,
					97,
					0,
					75,
					0,
					74,
					0,
					73,
					0,
					61,
					0,
					71,
					0,
					63,
					0,
					103
				};
				char[] array2 = text.ToCharArray();
				byte[] array3 = new byte[text.Length * 2];
				for (int i = 0; i < text.Length; i++)
				{
					int num = Convert.ToInt32(array2[i]);
					array3[i * 2 + 1] = (byte)((num ^ i) & 255);
					if (array[i * 2 + 1] != (int)array3[i * 2 + 1])
					{
						MessageBox.Show("Unvalid Password");
						return;
					}
				}
				MessageBox.Show(string.Format("Nice Work", Array.Empty<object>()));
			}
			catch (Exception ex)
			{
				MessageBox.Show(ex.Message);
			}
		}


```

# solution

```python
#!/usr/bin/python3

a=[0,70,0,77,0,67,0,68,0,127,0,91,0,89,0,45,0,87,0,86,0,85,0,63,0,120,0,96,0,62,0,58,0,118,0,34,0,38,0,97,0,75,0,74,0,73,0,61,0,71,0,63,0,103]



flag=bytearray(27)
for i in range(27):
	compare=a[i * 2 + 1]
	for num in range(256):
		if compare==((num ^ i )&255):
			flag[i]=num
			break
			
print(flag)

```
