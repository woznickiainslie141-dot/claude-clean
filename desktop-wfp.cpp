// SPDX-License-Identifier: MIT
// Outbound socket policy for a packaged Windows application. No driver or packet inspection.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <appmodel.h>
#include <fwpmu.h>
#include <sddl.h>
#include <userenv.h>
#include <bcrypt.h>
#include <filesystem>
#include <algorithm>
#include <cwctype>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "uuid.lib")
namespace fs = std::filesystem;
using std::wstring;
constexpr wchar_t family[] = L"Claude_pzs8sxrjxfjjc";
#ifdef DESKTOP_GUARD_FIXTURE
constexpr wchar_t product[] = L"Desktop Guard disposable test";
#else
constexpr wchar_t product[] = L"Claude Clean desktop guard v1";
#endif

void check(DWORD code, const char* operation) {
    if (code) throw std::runtime_error(std::string(operation) + " (" + std::to_string(code) + ")");
}
struct Handle {
    HANDLE value{};
    ~Handle() { if (value) CloseHandle(value); }
};
template<class T> struct WfpMemory {
    T* value{};
    ~WfpMemory() { if (value) FwpmFreeMemory0(reinterpret_cast<void**>(&value)); }
};
struct Engine {
    HANDLE value{};
    explicit Engine(bool dynamic = false) {
        FWPM_SESSION0 session{};
        session.flags = dynamic ? FWPM_SESSION_FLAG_DYNAMIC : 0;
        session.txnWaitTimeoutInMSec = 5000;
        check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &value), "open WFP");
    }
    ~Engine() { FwpmEngineClose0(value); }
};
struct Transaction {
    HANDLE engine;
    bool open = true;
    explicit Transaction(HANDLE h) : engine(h) { check(FwpmTransactionBegin0(h, 0), "begin transaction"); }
    void commit() { check(FwpmTransactionCommit0(engine), "commit transaction"); open = false; }
    ~Transaction() { if (open) FwpmTransactionAbort0(engine); }
};
GUID key(const wstring& label) {
    wstring text = wstring(product) + L"/" + label;
    BCRYPT_ALG_HANDLE alg{};
    check(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0), "open hash");
    BYTE digest[32]{};
    auto status = BCryptHash(alg, nullptr, 0, reinterpret_cast<BYTE*>(text.data()),
                             static_cast<ULONG>(text.size() * sizeof(wchar_t)), digest, sizeof(digest));
    BCryptCloseAlgorithmProvider(alg, 0);
    check(status, "policy key");
    GUID id{};
    memcpy(&id, digest, sizeof(id));
    return id;
}
struct Policy {
    GUID provider = key(L"provider"), layer = key(L"sublayer");
    PSECURITY_DESCRIPTOR acl{};
    PSID sid{};
    std::vector<fs::path> files;
    Policy() = default;
    explicit Policy(const fs::path& root) {
#ifndef DESKTOP_GUARD_FIXTURE
        UINT32 count = 0, size = 0;
        if (GetPackagesByPackageFamily(family, &count, nullptr, &size, nullptr) != ERROR_INSUFFICIENT_BUFFER || count != 1)
            throw std::runtime_error("Expected one registered Claude MSIX package");
        std::vector<PWSTR> names(count);
        std::vector<wchar_t> buffer(size);
        check(GetPackagesByPackageFamily(family, &count, names.data(), &size, buffer.data()), "registered package");
        size = 0;
        if (GetPackagePathByFullName(names[0], &size, nullptr) != ERROR_INSUFFICIENT_BUFFER)
            throw std::runtime_error("Package location unavailable");
        std::vector<wchar_t> path(size);
        check(GetPackagePathByFullName(names[0], &size, path.data()), "package path");
        if (!fs::equivalent(root, fs::path(path.data()) / L"app") || !fs::is_regular_file(root / L"Claude.exe"))
            throw std::runtime_error("Registered package changed; check again");
        check(DeriveAppContainerSidFromAppContainerName(family, &sid), "package SID");
#endif
        for (const auto& entry : fs::recursive_directory_iterator(root)) {
            if ((GetFileAttributesW(entry.path().c_str()) & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw std::runtime_error("Unexpected reparse point in package");
            if (entry.is_regular_file() && !_wcsicmp(entry.path().extension().c_str(), L".exe"))
                files.push_back(entry.path());
        }
        if (files.empty()) throw std::runtime_error("No packaged executables found");
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)", SDDL_REVISION_1, &acl, nullptr))
            check(GetLastError(), "policy ACL");
    }
    ~Policy() { if (sid) FreeSid(sid); if (acl) LocalFree(acl); }

    void containers(HANDLE engine, bool create) {
        WfpMemory<FWPM_PROVIDER0> p;
        DWORD result = FwpmProviderGetByKey0(engine, &provider, &p.value);
        if (result == FWP_E_PROVIDER_NOT_FOUND && create) {
            FWPM_PROVIDER0 item{};
            item.providerKey = provider; item.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
            item.displayData.name = const_cast<PWSTR>(product);
            check(FwpmProviderAdd0(engine, &item, acl), "add provider");
        } else {
            check(result, "read provider");
            if (p.value->flags != FWPM_PROVIDER_FLAG_PERSISTENT || !p.value->displayData.name ||
                wcscmp(p.value->displayData.name, product)) throw std::runtime_error("Unexpected provider");
        }
        WfpMemory<FWPM_SUBLAYER0> s;
        result = FwpmSubLayerGetByKey0(engine, &layer, &s.value);
        if (result == FWP_E_SUBLAYER_NOT_FOUND && create) {
            FWPM_SUBLAYER0 item{};
            item.subLayerKey = layer; item.providerKey = &provider; item.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
            item.displayData.name = const_cast<PWSTR>(product); item.weight = 0x9000;
            check(FwpmSubLayerAdd0(engine, &item, acl), "add sublayer");
        } else {
            check(result, "read sublayer");
            // BFE can assign a neighboring sublayer weight on collision. Filter priority within this sublayer is explicit.
            if (!s.value->providerKey || *s.value->providerKey != provider || !s.value->displayData.name ||
                wcscmp(s.value->displayData.name, product) ||
                s.value->flags != FWPM_SUBLAYER_FLAG_PERSISTENT) throw std::runtime_error("Unexpected sublayer");
        }
    }
    void rules(HANDLE engine, bool create, unsigned short port = 0) {
        auto apply = [&](const wstring& name, const FWPM_FILTER_CONDITION0& identity) {
            for (bool v6 : {false, true}) {
                if (port && v6) continue;
                FWPM_FILTER_CONDITION0 conditions[4]{identity};
                conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                conditions[1].conditionValue.type = FWP_UINT32;
                conditions[1].conditionValue.uint32 = 0x7f000001;
                conditions[2].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                conditions[2].conditionValue.type = FWP_UINT8; conditions[2].conditionValue.uint8 = IPPROTO_TCP;
                conditions[3].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                conditions[3].conditionValue.type = FWP_UINT16; conditions[3].conditionValue.uint16 = port;
                UINT64 weight = port ? 20 : 1;
                FWPM_FILTER0 f{};
                // A second session cannot add a different proxy exception for the same application.
                f.filterKey = key((v6 ? L"v6/" : L"v4/") + name + (port ? L"/lease" : L"/0"));
                f.displayData.name = const_cast<PWSTR>(product);
                f.flags = port ? 0 : FWPM_FILTER_FLAG_PERSISTENT;
                f.layerKey = v6 ? FWPM_LAYER_ALE_AUTH_CONNECT_V6 : FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                f.subLayerKey = layer; f.providerKey = &provider;
                f.weight.type = FWP_UINT64; f.weight.uint64 = &weight;
                f.numFilterConditions = port ? 4 : 1; f.filterCondition = conditions;
                f.action.type = port ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
                // Dynamic permits are always added fresh; an existing key belongs to another lease.
                WfpMemory<FWPM_FILTER0> existing;
                DWORD result = port ? FWP_E_FILTER_NOT_FOUND : FwpmFilterGetByKey0(engine, &f.filterKey, &existing.value);
                if (result == FWP_E_FILTER_NOT_FOUND && create) {
                    check(FwpmFilterAdd0(engine, &f, acl, nullptr), "add scoped filter");
                } else {
                    check(result, "read persistent block");
                    auto& old = *existing.value;
                    if (!old.providerKey || *old.providerKey != provider || old.subLayerKey != layer ||
                        old.layerKey != f.layerKey || old.action.type != FWP_ACTION_BLOCK ||
                        (old.flags & (FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_DISABLED)) != FWPM_FILTER_FLAG_PERSISTENT ||
                        old.weight.type != FWP_UINT64 ||
                        !old.weight.uint64 || *old.weight.uint64 != weight || old.numFilterConditions != 1)
                        throw std::runtime_error("Unexpected block rule");
                    auto& cond = old.filterCondition[0];
                    if (cond.fieldKey != identity.fieldKey || cond.matchType != FWP_MATCH_EQUAL ||
                        cond.conditionValue.type != identity.conditionValue.type) throw std::runtime_error("Wrong rule scope");
                    if (cond.conditionValue.type == FWP_SID) {
                        if (!EqualSid(cond.conditionValue.sid, sid)) throw std::runtime_error("Wrong package identity");
                    } else {
                        auto a = cond.conditionValue.byteBlob, b = identity.conditionValue.byteBlob;
                        if (!a || a->size != b->size || memcmp(a->data, b->data, b->size))
                            throw std::runtime_error("Wrong executable identity");
                    }
                }
            }
        };
        if (sid) {
            FWPM_FILTER_CONDITION0 c{}; c.fieldKey = FWPM_CONDITION_ALE_PACKAGE_ID;
            c.conditionValue.type = FWP_SID; c.conditionValue.sid = static_cast<SID*>(sid);
            apply(L"package", c);
        }
        for (const auto& path : files) {
            WfpMemory<FWP_BYTE_BLOB> id;
            check(FwpmGetAppIdFromFileName0(path.c_str(), &id.value), "get executable identity");
            FWPM_FILTER_CONDITION0 c{}; c.fieldKey = FWPM_CONDITION_ALE_APP_ID;
            c.conditionValue.type = FWP_BYTE_BLOB_TYPE; c.conditionValue.byteBlob = id.value;
            wstring name = path.wstring();
            std::transform(name.begin(), name.end(), name.begin(), towlower);
            apply(name, c);
        }
    }
    void remove(HANDLE engine) {
        WfpMemory<FWPM_PROVIDER0> installed;
        DWORD result = FwpmProviderGetByKey0(engine, &provider, &installed.value);
        if (result == FWP_E_PROVIDER_NOT_FOUND) return;
        check(result, "locate owned provider");
        containers(engine, false);
        std::vector<GUID> keys;
        for (const GUID& transport : {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6}) {
            HANDLE enumeration{};
            FWPM_FILTER_ENUM_TEMPLATE0 query{}; query.providerKey = &provider; query.layerKey = transport;
            query.actionMask = 0xffffffff;
            check(FwpmFilterCreateEnumHandle0(engine, &query, &enumeration), "list owned rules");
            for (;;) {
                WfpMemory<FWPM_FILTER0*> page; UINT32 count{};
                check(FwpmFilterEnum0(engine, enumeration, 128, &page.value, &count), "read owned rules");
                if (!count) break;
                for (UINT32 i = 0; i < count; ++i) {
                    auto f = page.value[i];
                    if (f->subLayerKey != layer || f->action.type != FWP_ACTION_BLOCK)
                        throw std::runtime_error("Finish the guarded session before removal");
                    keys.push_back(f->filterKey);
                }
            }
            check(FwpmFilterDestroyEnumHandle0(engine, enumeration), "close enumeration");
        }
        for (auto& id : keys) check(FwpmFilterDeleteByKey0(engine, &id), "remove owned rule");
        check(FwpmSubLayerDeleteByKey0(engine, &layer), "remove sublayer");
        check(FwpmProviderDeleteByKey0(engine, &provider), "remove provider");
    }
};

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 2 && wstring(argv[1]) == L"remove") {
            Policy policy; Engine engine; Transaction tx(engine.value);
            policy.remove(engine.value); tx.commit(); return 0;
        }
        if (argc < 3) throw std::runtime_error("Expected install, status, remove or lease and package directory");
        const wstring mode = argv[1];
        Policy policy(fs::canonical(argv[2]));
        Engine base;
        if ((mode != L"install" && mode != L"status" && mode != L"lease") ||
            argc != (mode == L"lease" ? 6 : 3)) throw std::runtime_error("Invalid operation");
        if (mode != L"status") {
            Transaction tx(base.value); policy.containers(base.value, true); policy.rules(base.value, true); tx.commit();
        }
        policy.containers(base.value, false); policy.rules(base.value, false);
        if (mode != L"lease") {
            std::wcout << L"Persistent outbound blocks verified for " << policy.files.size() << L" executables.\n";
            if (policy.sid) {
                GUID id = key(L"v4/package/lease");
                WfpMemory<FWPM_FILTER0> active;
                DWORD r = FwpmFilterGetByKey0(base.value, &id, &active.value);
                if (r != FWP_E_FILTER_NOT_FOUND) check(r, "read desktop session status");
                std::wcout << (active.value ? L"Temporary relay permit active.\n" : L"No temporary relay permit.\n");
            }
            return 0;
        }
        ULONG port = std::stoul(argv[3]), pid = std::stoul(argv[4]);
        wstring token = argv[5];
        if (!port || port > 65535 || !pid || token.size() != 32 || token.find_first_not_of(L"0123456789abcdef") != wstring::npos)
            throw std::runtime_error("Invalid lease arguments");
        Handle owner{OpenProcess(SYNCHRONIZE, FALSE, pid)};
        wstring prefix = L"Local\\ClaudeCleanDesktop-" + token;
        Handle ready{OpenEventW(EVENT_MODIFY_STATE, FALSE, (prefix + L"-ready").c_str())};
        Handle stop{OpenEventW(SYNCHRONIZE, FALSE, (prefix + L"-stop").c_str())};
        if (!owner.value || !ready.value || !stop.value) throw std::runtime_error("Guard process or session events missing");
        HANDLE ends[] = {owner.value, stop.value};
        if (WaitForMultipleObjects(2, ends, FALSE, 0) != WAIT_TIMEOUT) return 0;
        Engine lease(true);
        Transaction tx(lease.value); policy.rules(lease.value, true, static_cast<USHORT>(port)); tx.commit();
        if (!SetEvent(ready.value)) check(GetLastError(), "signal readiness");
        if (WaitForMultipleObjects(2, ends, FALSE, INFINITE) == WAIT_FAILED) check(GetLastError(), "wait for guard");
        // Closing the dynamic WFP engine handle revokes the sole loopback exception.
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
