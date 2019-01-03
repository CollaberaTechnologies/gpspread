using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;
using Spire.Pdf;
using Spire.Doc.Documents;
using WebApplication6.Models;
using Spire.Pdf.HtmlConverter;
using System.Threading;
using System.IO;

namespace WebApplication6.Controllers
{
    public class DashboardController : Controller
    {
        private LIVEDBEntities7 db = new LIVEDBEntities7();
        public V5Entities6 v5 = new V5Entities6();
        public void cache()
        {
            Response.Cache.SetCacheability(HttpCacheability.NoCache);
            Response.Cache.AppendCacheExtension("no-store, must-revalidate");
        }
        [HttpGet]
        public ActionResult Dash()
        {
            cache();
            if (Session["userid"] == null)
            {
                return RedirectToAction("Login", "Account");
            }
            else
            {
                if (TempData["alert"] != null)
                {
                    ViewBag.alert = TempData["alert"];
                }
                else
                {
                    ViewBag.alert = null;
                }
                if (TempData["rights"] != null)
                {
                    ViewBag.rights = TempData["rights"];

                }
                else
                {
                    ViewBag.rights = TempData["rights"];

                }
                long uid = (long)Session["userid"];
                ViewBag.status = db.RecrutierCandidateTrackingCountActive(uid);
                ViewBag.inactive = db.RecrutierCandidateTrackingCountInActive(uid);
                ViewBag.FTE = db.RecrutierCandidateTrackingCountFTE(uid);
                ViewBag.Perm = db.RecrutierCandidateTrackingCountPermanant(uid);
                ViewBag.VALUE = db.RecrutierTrackingSystem(uid);
                return View();
            }
        }
        public ActionResult Details(string clid, string name)
        {
            ViewBag.VALUE = db.RecrutierCandidateTrackingDetails(name, clid);
            return View();
        }
        [HttpGet]
        public ActionResult getstatus(string clid, string name, string client)
        {
            ViewBag.a = clid;
            ViewBag.b = name;
            ViewBag.c = client;
            return View();
        }
        [HttpPost]
        public ActionResult getstatus(string clid, string name, decimal GP, string GPM, string clname)
        {
            long uid = (long)Session["userid"];
            ViewBag.insert = db.RecruiterTracking_data(uid, clid, name, GP, GPM, clname);
            TempData["alert"] = "Data Updated Successfully";
            return RedirectToAction("Dash");
        }
        public ActionResult logout()
        {
            Response.Cache.SetCacheability(HttpCacheability.NoCache);
            Response.Cache.AppendCacheExtension("no-store, must-revalidate");
            Session.Abandon();
            return RedirectToAction("Login", "Account");
        }
        public ActionResult GetFile(long rid)
        {
            string data = v5.HC_RESUME_DOCUMENTS.Where(x => x.ResID == rid).Select(x => x.ResHTMLText).FirstOrDefault();
            if (data == null)
            {
                data = "<b>Resume Does Not Exists!!</b>";
            }
            return Content(data, "text/html");
        }
        [HttpGet]
        public ActionResult cosearch()
        {
            string countryname = (string)Session["country"];
            long country = v5.HCM_COUNTRY.Where(x => x.Title == countryname).Select(y => y.RID).FirstOrDefault();
            ViewBag.grid = v5.IHD_COSEARCH_2(country);
            countrylist(country);
            location(country, new long[] { });
            skill(new long[] { 0 });
            optionalskill(new long[] { 0 });
            return View();
        }

        [HttpPost]
        public ActionResult cosearch(long countries, long[] locations, long[] Mandatory, long[] optional, HCM_LOCATIONS model, IHD_COSEARCH_REPORT data)
        {
            string ip = Request.UserHostAddress;
            var username = (long)Session["userid"];
            DateTime logindate = Convert.ToDateTime(Session["logintime"]);
            var logintime = Session["Time"].ToString();
            var info = v5.IHD_COSEARCH_REPORT.Where(x => x.UserID == username && x.LOGINtimestr == logintime).FirstOrDefault();
            if (info == null)
            {
                data.IPAddress = ip;
                data.UserID = (long)Session["userid"];
                data.LOGINDate = logindate;
                data.LOGINtimestr = logintime;
                data.Counts = 1;
                v5.IHD_COSEARCH_REPORT.Add(data);
            }
            else
            {

                info.Counts = info.Counts + 1;
            }
            v5.SaveChanges();
            string countryname = (string)Session["country"];
            long country = v5.HCM_COUNTRY.Where(x => x.Title == countryname).Select(y => y.RID).FirstOrDefault();
            string locationdata = string.Empty;
            string skilldata = string.Empty;
            string optional11 = string.Empty;
            if (locations == null) { }
            else if (locations[0] == 0) { }
            else
            {
                foreach (var item in locations)
                {
                    if (locationdata.Length > 0)
                    {
                        locationdata += ","; // Add a comma if data already exists
                    }

                    locationdata += "" + item + "";
                }
            }
            if (Mandatory == null) { }
            else
            {
                foreach (var item in Mandatory)
                {
                    if (skilldata.Length > 0)
                    {
                        skilldata += ","; // Add a comma if data already exists
                    }

                    skilldata += "" + item + "";
                }

            }
            if (optional == null) { }
            else
            {
                foreach (var item in optional)
                {
                    if (optional11.Length > 0)
                    {
                        optional11 += ","; // Add a comma if data already exists
                    }
                    optional11 += "" + item + "";
                }

            }
            ViewBag.grid = v5.IHD_COSEARCH_SKILL_4(locationdata, skilldata, optional11, countries);
            countrylist(countries);
            optionalskill(optional);
            location(countries, locations);
            skill(Mandatory);
            return View(model);
        }
        public void countrylist(long countryid)
        {
            List<SelectListItem> countries = v5.HCM_COUNTRY.OrderBy(x => x.Title).Select(c => new SelectListItem
            {
                Value = c.RID.ToString(),
                Text = c.Title,
                Selected = (c.RID == countryid ? true : false)
            }).ToList();
            ViewBag.country = countries;
        }
        public ActionResult location(long countryid, long[] selected)
        {
            ViewBag.location = new SelectList(v5.IHD_GP_Spread_Location_2(countryid), "RID", "LocationTitle", selected);

            return Json(new SelectList(v5.IHD_GP_Spread_Location_2(countryid), "RID", "LocationTitle", selected), JsonRequestBehavior.AllowGet);
        }
        public void skill(long[] selecteddata)
        {
            List<SelectListItem> skills = v5.HCM_SKILLS.OrderBy(x => x.Title).Select(c => new SelectListItem
            {
                Value = c.RID.ToString(),
                Text = c.Title
            }).Distinct().ToList();
            ViewBag.skill = new MultiSelectList(skills, "Value", "Text", selecteddata);
        }
        public void optionalskill(long[] selecteddata)
        {
            List<SelectListItem> skills = v5.HCM_SKILLS.OrderBy(x => x.Title).Select(c => new SelectListItem
            {
                Value = c.RID.ToString(),
                Text = c.Title
            }).Distinct().ToList();
            ViewBag.skilldata = new MultiSelectList(skills, "Value", "Text", selecteddata);
        }
        public ActionResult CandidateContacts()
        {
            List<SelectListItem> skills = v5.HCM_SKILLS.OrderBy(x => x.Title).Select(c => new SelectListItem
            {
                Value = c.RID.ToString(),
                Text = c.Title
            }).Distinct().ToList();
            return null;
        }

        //CANDIDATE JOURNAL

    }
}
   


