Imports System.Net.NetworkInformation
Imports Microsoft.Win32

Module Module1

    Sub Main()
        Dim result As Boolean = findVM()
        If result = True Then
            Console.WriteLine("Virtual environment detected.")
        Else
            Console.WriteLine("Virtual environment not detected.")
        End If

        Console.ReadLine()
    End Sub


    Function findVM() As Boolean
        'Check for Sandboxie
        Dim sbProcs() As String = {"SandboxieDcomLaunch", "SandboxieRpcSs", "SandMan"}

        For c As Integer = 0 To sbProcs.Length - 1
            Dim sbp() As Process
            sbp = Process.GetProcessesByName(sbProcs(c).ToString)
            If sbp.Length > 0 Then
                Return True
                Exit Function
            End If
        Next


        'Scan for known MAC addresses
        Dim nics() As NetworkInterface = NetworkInterface.GetAllNetworkInterfaces
        Dim vmMacs() As String = {"00:05:69",
            "00:0C:29",
            "00:1C:14",
            "00:50:56",
            "08:00:27",
            "00-03-FF",
            "00-1C-42",
            "00-0F-4B",
            "00-16-3E"}

        Dim chkMac As String
        For a As Integer = 0 To nics.Length - 1
            chkMac = nics(a).GetPhysicalAddress.ToString

            For b As Integer = 0 To vmMacs.Length - 1
                If chkMac.Contains(vmMacs(b).ToString) Then
                    Return True
                    Exit Function
                End If
            Next
        Next


        'Check registry sub-keys for VM entries
        Dim keysHKLM() As String = {"SOFTWARE\Vmware Tools",
           "SOFTWARE\Vmware Inc.",
           "SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_VMware_&Prod_VMware_Virtual_S",
           "SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\root#vmwvmcihostdev",
           "SYSTEM\CurrentControlSet\Control\VirtualDeviceDrivers",
           "SYSTEM\CurrentControlSet\Enum\SCSI\CdRom&Ven_XBOX&Prod_CD-ROM",
           "SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_VBOX&Prod_HARDDISK",
           "SYSTEM\CurrentControlSet\Enum\SCSI\CdRom&Ven_NECVMWar&Prod_VMware_SATA_CD01",
           "SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_NVMe&Prod_VMware_Virtual_N"}

        For c As Integer = 0 To keysHKLM.Length - 1
            If Not Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keysHKLM(c)) Is Nothing Then
                Return True
                Exit Function
            End If
        Next


        'Check registry key values
        Dim keyVal() As String = {"SYSTEM\HardwareConfig\Current\ComputerIds",
            "HARDWARE\DEVICEMAP\Scsi\Scsi Port3\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
            "SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"}

        For d As Integer = 0 To keyVal.Length - 1
            If Not Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyVal(d).ToString) Is Nothing Then

                Dim regChk As RegistryKey = Registry.LocalMachine.OpenSubKey(keyVal(d).ToString)
                For Each ValueName As String In regChk.GetValueNames()
                    Dim regValue As Object = regChk.GetValue(ValueName)
                    If regValue IsNot Nothing Then
                        Dim regStr As String = regValue.ToString
                        If (regStr.ToLower.Contains("vmware") = True Or regStr.ToLower.Contains("virtualmachine") = True) Then
                            Return True
                            Exit Function
                        End If
                    End If
                Next
                regChk.Close()

            End If
        Next


        'Check user/computer name for key words
        Dim nameVals() As String = {"vmware",
            "vbox",
            "vmbox",
            "virtualbox",
            "box",
            "dummy",
            "honeypot",
            "innotek", 'innotek gmbh
            "VMXh",
            "virtual",
            "kvm",
            "hyperv"}

        Dim chkName() As String = {Environment.UserName, Environment.MachineName}
        For e As Integer = 0 To chkName.Length - 1
            Dim chkVal As String = chkName(e).ToString.ToLower

            For f As Integer = 0 To nameVals.Length - 1
                If chkVal.Contains(nameVals(f)) Then
                    Return True
                    Exit Function
                End If
            Next
        Next


        'If nothing, return FALSE
        Return False
    End Function

End Module
